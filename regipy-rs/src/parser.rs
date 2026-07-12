//! Core REGF (Windows registry hive) parser.
//!
//! This is a faithful port of regipy's Python parser (`regipy/registry.py` +
//! `regipy/structs.py`). Output semantics intentionally match the Python
//! implementation byte-for-byte so the two backends can be compared 1:1 by
//! `regipy_tests/comparison_test.py` — including quirks such as:
//!
//! - Key/value names decoded with the "replace" error handler (U+FFFD).
//! - `try_decode_binary` decode order: strict UTF-16LE, then strict UTF-8,
//!   then hex (as_json) / raw bytes.
//! - String values trimmed to 256 chars when `trim_values` is set, while hex
//!   dumps are trimmed to the caller-provided `max_len`.
//! - A subkey-list with an unknown signature yields no subkeys (no error).
//! - Partially parsed value lists: a bad VK record silently ends iteration,
//!   while a bad VK *offset list* is a parsing error.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

pub const REGF_HEADER_SIZE: usize = 4096;
pub const HBIN_HEADER_SIZE: usize = 32;
/// Values larger than this are stored in "big data" (db) segments.
pub const BIG_DATA_THRESHOLD: u32 = 0x3FD8;
/// Max length of decoded strings when trimming (regipy.utils.MAX_LEN).
pub const MAX_LEN: usize = 256;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ParseError {
    Io(std::io::Error),
    /// Maps to regipy's RegistryParsingException.
    Parsing(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Io(e) => write!(f, "{e}"),
            ParseError::Parsing(msg) => write!(f, "{msg}"),
        }
    }
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

fn oob(offset: usize, what: &str) -> ParseError {
    ParseError::Parsing(format!("Read out of bounds at offset {offset} while reading {what}"))
}

// ─── Raw readers ─────────────────────────────────────────────────────────────

#[inline]
fn need(data: &[u8], off: usize, len: usize, what: &str) -> Result<()> {
    if off.checked_add(len).is_none_or(|end| end > data.len()) {
        Err(oob(off, what))
    } else {
        Ok(())
    }
}

#[inline]
fn u16_at(data: &[u8], off: usize, what: &str) -> Result<u16> {
    need(data, off, 2, what)?;
    Ok(u16::from_le_bytes([data[off], data[off + 1]]))
}

#[inline]
fn u32_at(data: &[u8], off: usize, what: &str) -> Result<u32> {
    need(data, off, 4, what)?;
    Ok(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

#[inline]
fn u64_at(data: &[u8], off: usize, what: &str) -> Result<u64> {
    need(data, off, 8, what)?;
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[off..off + 8]);
    Ok(u64::from_le_bytes(b))
}

#[inline]
fn slice_at<'a>(data: &'a [u8], off: usize, len: usize, what: &str) -> Result<&'a [u8]> {
    need(data, off, len, what)?;
    Ok(&data[off..off + len])
}

// ─── String decoding (Python codec semantics) ────────────────────────────────

/// bytes.decode("ascii", errors="replace")
pub fn decode_ascii_replace(data: &[u8]) -> String {
    data.iter().map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' }).collect()
}

#[inline]
fn utf16le_units(data: &[u8]) -> impl Iterator<Item = u16> + '_ {
    data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]))
}

/// bytes.decode("utf-16-le", errors="replace")
pub fn decode_utf16le_replace(data: &[u8]) -> String {
    let mut s: String = char::decode_utf16(utf16le_units(data)).map(|r| r.unwrap_or('\u{FFFD}')).collect();
    if !data.len().is_multiple_of(2) {
        // Python replaces the trailing lone byte with a single U+FFFD
        s.push('\u{FFFD}');
    }
    s
}

/// bytes.decode("utf-16-le") — strict. None on any error (odd length, lone surrogate).
/// Decodes lazily so it fails fast on invalid input, like CPython's C codec —
/// values can reference multi-megabyte slices and must not be materialized
/// up-front just to fail on the first unit.
fn decode_utf16le_strict(data: &[u8]) -> Option<String> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    char::decode_utf16(utf16le_units(data)).collect::<std::result::Result<String, _>>().ok()
}

/// Python str[:max_len] (by code points).
fn truncate_chars(s: &str, max_len: usize) -> String {
    match s.char_indices().nth(max_len) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// binascii.b2a_hex equivalent (lookup table — the formatter machinery is far
/// too slow for multi-megabyte buffers).
pub fn hex_lower(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len() * 2);
    for &b in data {
        out.push(HEX_CHARS[(b >> 4) as usize]);
        out.push(HEX_CHARS[(b & 0x0F) as usize]);
    }
    // Safety by construction: only ASCII hex digits are pushed.
    String::from_utf8(out).expect("hex output is ASCII")
}

/// Hex-encode only as many bytes as can survive truncation to `max_chars`
/// (Python hexes the full buffer and then slices; the output is identical).
pub fn hex_lower_trimmed(data: &[u8], max_chars: usize) -> String {
    let take = data.len().min(max_chars.div_ceil(2));
    truncate_chars(&hex_lower(&data[..take]), max_chars)
}

// ─── FILETIME conversion (regipy.utils.convert_wintime semantics) ───────────
//
// Python computes: datetime(1601,1,1,utc) + timedelta(microseconds=wintime/10)
// and clamps to the 1601-01-01 epoch on OverflowError. `wintime/10` is an f64
// division and timedelta rounds fractional microseconds half-to-even; both are
// replicated exactly here (verified by the fuzz test in comparison_test.py).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CivilDateTime {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub microsecond: u32,
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of days_from_civil.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

const MICROS_PER_DAY: i64 = 86_400_000_000;

fn filetime_epoch_days() -> i64 {
    days_from_civil(1601, 1, 1)
}

/// Highest microsecond count representable as a Python datetime
/// (9999-12-31 23:59:59.999999 relative to the 1601-01-01 epoch).
fn max_filetime_micros() -> i64 {
    (days_from_civil(9999, 12, 31) - filetime_epoch_days()) * MICROS_PER_DAY + (MICROS_PER_DAY - 1)
}

const FILETIME_EPOCH: CivilDateTime =
    CivilDateTime { year: 1601, month: 1, day: 1, hour: 0, minute: 0, second: 0, microsecond: 0 };

/// Correctly-rounded x/10 as f64, matching Python's int/int true division.
/// (`x as f64 / 10.0` would round twice: once at the u64→f64 conversion and
/// once at the division.)
fn u64_div10_f64(x: u64) -> f64 {
    let n = (x as u128) << 63;
    let mut q = n / 10;
    if n % 10 != 0 {
        // Sticky bit: the quotient's LSB sits far below the f64 rounding
        // point except in exact-tie cases, where a non-zero remainder must
        // break the tie upward.
        q |= 1;
    }
    (q as f64) * 2f64.powi(-63)
}

pub fn filetime_to_civil(wintime: u64) -> CivilDateTime {
    // Python: us = wintime / 10 (correctly-rounded int division to f64),
    // then timedelta rounds half-to-even.
    let us_f = u64_div10_f64(wintime);
    let rounded = us_f.round_ties_even();
    if !(0.0..=max_filetime_micros() as f64).contains(&rounded) {
        // Python catches the OverflowError and returns the epoch.
        return FILETIME_EPOCH;
    }
    let micros = rounded as i64;
    if micros > max_filetime_micros() {
        return FILETIME_EPOCH;
    }
    let days = micros.div_euclid(MICROS_PER_DAY);
    let rem = micros.rem_euclid(MICROS_PER_DAY);
    let (year, month, day) = civil_from_days(filetime_epoch_days() + days);
    let secs = rem / 1_000_000;
    CivilDateTime {
        year: year as i32,
        month: month as u8,
        day: day as u8,
        hour: (secs / 3600) as u8,
        minute: ((secs / 60) % 60) as u8,
        second: (secs % 60) as u8,
        microsecond: (rem % 1_000_000) as u32,
    }
}

/// datetime.isoformat() for a UTC-aware datetime: microseconds are printed
/// (6 digits) only when non-zero.
pub fn filetime_to_iso(wintime: u64) -> String {
    let c = filetime_to_civil(wintime);
    if c.microsecond == 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+00:00",
            c.year, c.month, c.day, c.hour, c.minute, c.second, c.microsecond
        )
    }
}

// ─── REGF header ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RegfHeader {
    pub primary_sequence_num: u32,
    pub secondary_sequence_num: u32,
    pub last_modification_time: u64,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,
    pub file_format: u32,
    pub root_key_offset: u32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32,
    pub file_name: String,
    pub checksum: u32,
}

fn parse_regf_header(data: &[u8]) -> Result<RegfHeader> {
    if slice_at(data, 0, 4, "REGF signature")? != b"regf" {
        return Err(ParseError::Parsing("Invalid REGF signature".to_string()));
    }
    let file_name_raw = slice_at(data, 48, 64, "REGF file name")?;
    // PaddedString(64, "utf-16-le"): decode then strip trailing NULs.
    let file_name = decode_utf16le_replace(file_name_raw).trim_end_matches('\0').to_string();
    Ok(RegfHeader {
        primary_sequence_num: u32_at(data, 4, "REGF header")?,
        secondary_sequence_num: u32_at(data, 8, "REGF header")?,
        last_modification_time: u64_at(data, 12, "REGF header")?,
        major_version: u32_at(data, 20, "REGF header")?,
        minor_version: u32_at(data, 24, "REGF header")?,
        file_type: u32_at(data, 28, "REGF header")?,
        file_format: u32_at(data, 32, "REGF header")?,
        root_key_offset: u32_at(data, 36, "REGF header")?,
        hive_bins_data_size: u32_at(data, 40, "REGF header")?,
        clustering_factor: u32_at(data, 44, "REGF header")?,
        file_name,
        checksum: u32_at(data, 508, "REGF header")?,
    })
}

// ─── NK record ───────────────────────────────────────────────────────────────

pub const KEY_VOLATILE: u16 = 0x0001;
pub const KEY_HIVE_EXIT: u16 = 0x0002;
pub const KEY_HIVE_ENTRY: u16 = 0x0004;
pub const KEY_NO_DELETE: u16 = 0x0008;
pub const KEY_SYM_LINK: u16 = 0x0010;
pub const KEY_COMP_NAME: u16 = 0x0020;
pub const KEY_PREDEF_HANDLE: u16 = 0x0040;

/// A parsed CM_KEY_NODE. `offset` is the file offset of the `flags` field
/// (i.e. cell payload + 2, past the "nk" signature), matching the stream
/// position regipy's Python NKRecord parses from.
#[derive(Debug, Clone)]
pub struct NkRecord {
    pub offset: usize,
    pub flags: u16,
    pub last_modified: u64,
    pub access_bits: [u8; 4],
    pub parent_key_offset: u32,
    pub subkey_count: u32,
    pub volatile_subkey_count: u32,
    pub subkeys_list_offset: u32,
    pub volatile_subkeys_list_offset: u32,
    pub values_count: u32,
    pub values_list_offset: u32,
    pub security_key_offset: u32,
    pub class_name_offset: u32,
    pub largest_sk_name: u32,
    pub largest_sk_class_name: u32,
    pub largest_value_name: u32,
    pub largest_value_data: u32,
    pub key_name_size: u16,
    pub class_name_size: u16,
    pub key_name_raw: Vec<u8>,
    pub name: String,
}

pub fn parse_nk(data: &[u8], off: usize) -> Result<NkRecord> {
    need(data, off, 74, "NK record")?;
    let flags = u16_at(data, off, "NK flags")?;
    let key_name_size = u16_at(data, off + 70, "NK name size")?;
    let key_name_raw = slice_at(data, off + 74, key_name_size as usize, "NK name")?.to_vec();
    let name = if flags & KEY_COMP_NAME != 0 {
        decode_ascii_replace(&key_name_raw)
    } else {
        decode_utf16le_replace(&key_name_raw)
    };
    let mut access_bits = [0u8; 4];
    access_bits.copy_from_slice(&data[off + 10..off + 14]);
    Ok(NkRecord {
        offset: off,
        flags,
        last_modified: u64_at(data, off + 2, "NK timestamp")?,
        access_bits,
        parent_key_offset: u32_at(data, off + 14, "NK")?,
        subkey_count: u32_at(data, off + 18, "NK")?,
        volatile_subkey_count: u32_at(data, off + 22, "NK")?,
        subkeys_list_offset: u32_at(data, off + 26, "NK")?,
        volatile_subkeys_list_offset: u32_at(data, off + 30, "NK")?,
        values_count: u32_at(data, off + 34, "NK")?,
        values_list_offset: u32_at(data, off + 38, "NK")?,
        security_key_offset: u32_at(data, off + 42, "NK")?,
        class_name_offset: u32_at(data, off + 46, "NK")?,
        largest_sk_name: u32_at(data, off + 50, "NK")?,
        largest_sk_class_name: u32_at(data, off + 54, "NK")?,
        largest_value_name: u32_at(data, off + 58, "NK")?,
        largest_value_data: u32_at(data, off + 62, "NK")?,
        key_name_size,
        class_name_size: u16_at(data, off + 72, "NK class name size")?,
        key_name_raw,
        name,
    })
}

// ─── Hive ────────────────────────────────────────────────────────────────────

pub struct Hive {
    pub data: Vec<u8>,
    pub header: RegfHeader,
    pub root: NkRecord,
}

impl Hive {
    pub fn from_file(path: &str) -> Result<Arc<Hive>> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Arc<Hive>> {
        let header = parse_regf_header(&data)?;
        // The Python parser takes the first allocated cell of the first hbin
        // as the root NK record (not header.root_key_offset).
        if slice_at(&data, REGF_HEADER_SIZE, 4, "HBIN signature")? != b"hbin" {
            return Err(ParseError::Parsing("Invalid HBIN signature".to_string()));
        }
        let hbin_size = u32_at(&data, REGF_HEADER_SIZE + 8, "HBIN size")? as usize;
        let hbin_end = REGF_HEADER_SIZE.saturating_add(hbin_size).min(data.len());
        let mut pos = REGF_HEADER_SIZE + HBIN_HEADER_SIZE;
        let root_off = loop {
            if pos + 4 > hbin_end {
                return Err(ParseError::Parsing("No allocated root cell found in first HBIN".to_string()));
            }
            let size = u32_at(&data, pos, "cell size")? as i32;
            if size >= 0 {
                // Unallocated cell: the Python parser scans forward 4 bytes at a time.
                pos += 4;
                continue;
            }
            // Allocated: payload starts after the size field; skip the 2-byte
            // "nk" signature to land on the flags field.
            break pos + 4 + 2;
        };
        let root = parse_nk(&data, root_off)?;
        Ok(Arc::new(Hive { data, header, root }))
    }
}

// ─── Subkey lists ────────────────────────────────────────────────────────────

/// Result of enumerating a subkey list: the successfully parsed prefix and,
/// if enumeration failed midway, the error. This mirrors Python generator
/// semantics where earlier elements are yielded before the exception raises.
pub struct SubkeyList {
    pub subkeys: Vec<NkRecord>,
    pub error: Option<ParseError>,
}

fn parse_leaf_elements(data: &[u8], pos: usize, stride: usize, out: &mut Vec<NkRecord>) -> Result<()> {
    let count = u16_at(data, pos, "subkey list count")? as usize;
    for i in 0..count {
        let elem_off = pos + 2 + stride * i;
        let key_node_offset = u32_at(data, elem_off, "subkey element")? as usize;
        // Skip the 4-byte cell size and the 2-byte "nk" signature.
        let nk_off = REGF_HEADER_SIZE + key_node_offset + 4 + 2;
        out.push(parse_nk(data, nk_off)?);
    }
    Ok(())
}

/// Enumerate the subkeys of `nk`, in on-disk list order (Python: NKRecord.iter_subkeys).
pub fn list_subkeys(hive: &Hive, nk: &NkRecord) -> SubkeyList {
    let mut out = Vec::new();
    let error = list_subkeys_inner(&hive.data, nk, &mut out).err();
    SubkeyList { subkeys: out, error }
}

fn list_subkeys_inner(data: &[u8], nk: &NkRecord, out: &mut Vec<NkRecord>) -> Result<()> {
    if nk.subkey_count == 0 {
        return Ok(());
    }
    // subkey_count comes from disk and may be corrupt — cap the pre-allocation.
    out.reserve((nk.subkey_count as usize).min(4096));
    let payload = REGF_HEADER_SIZE + 4 + nk.subkeys_list_offset as usize;
    let sig = slice_at(data, payload, 2, "subkey list signature")
        .map_err(|_| ParseError::Parsing(format!("Bad subkey at offset {payload}")))?;
    match sig {
        b"lf" | b"lh" => parse_leaf_elements(data, payload + 2, 8, out),
        b"li" => parse_leaf_elements(data, payload + 2, 4, out),
        b"ri" => {
            let count = u16_at(data, payload + 2, "ri count")? as usize;
            for i in 0..count {
                let elem = u32_at(data, payload + 4 + 4 * i, "ri element")? as usize;
                let child = REGF_HEADER_SIZE + 4 + elem;
                let child_sig = slice_at(data, child, 2, "subkey list signature")?;
                match child_sig {
                    b"lf" | b"lh" => parse_leaf_elements(data, child + 2, 8, out)?,
                    b"li" => parse_leaf_elements(data, child + 2, 4, out)?,
                    other => {
                        return Err(ParseError::Parsing(format!(
                            "Expected a known signature, got: {other:?} at offset {child}"
                        )))
                    }
                }
            }
            Ok(())
        }
        // Python silently yields nothing for unknown list signatures.
        _ => Ok(()),
    }
}

/// Case-insensitive subkey lookup (Python: NKRecord.get_subkey).
pub fn find_subkey(hive: &Hive, nk: &NkRecord, name: &str) -> Result<Option<NkRecord>> {
    let target = name.to_uppercase();
    let list = list_subkeys(hive, nk);
    for sk in list.subkeys {
        if sk.name.to_uppercase() == target {
            return Ok(Some(sk));
        }
    }
    match list.error {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

// ─── VK records and value decoding ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VkHeader {
    // name_size and flags are consumed during name decoding in parse_vk but
    // kept here so the struct mirrors the full on-disk VK record.
    #[allow(dead_code)]
    pub name_size: u16,
    pub data_size: u32,
    pub data_offset: u32,
    pub data_type: u32,
    #[allow(dead_code)]
    pub flags: u16,
    pub name: String,
}

pub const VALUE_COMP_NAME: u16 = 0x0001;

fn parse_vk(data: &[u8], payload: usize) -> Result<VkHeader> {
    if slice_at(data, payload, 2, "VK signature")? != b"vk" {
        return Err(ParseError::Parsing(format!("Bad VK signature at offset {payload}")));
    }
    let name_size = u16_at(data, payload + 2, "VK")?;
    let data_size = u32_at(data, payload + 4, "VK")?;
    let data_offset = u32_at(data, payload + 8, "VK")?;
    let data_type = u32_at(data, payload + 12, "VK")?;
    let flags = u16_at(data, payload + 16, "VK")?;
    let name_raw = slice_at(data, payload + 20, name_size as usize, "VK name")?;
    let name = if name_size == 0 {
        "(default)".to_string()
    } else if flags & VALUE_COMP_NAME != 0 {
        decode_ascii_replace(name_raw)
    } else {
        decode_utf16le_replace(name_raw)
    };
    Ok(VkHeader { name_size, data_size, data_offset, data_type, flags, name })
}

pub fn value_type_name(t: u32) -> Option<&'static str> {
    Some(match t {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        16 => "REG_FILETIME",
        _ => return None,
    })
}

/// How the value type is surfaced to Python:
/// - Named: str, e.g. "REG_SZ" (also for DEVPROP-wrapped known types)
/// - NumStr: str(int) for unknown types on the normal path
/// - Num: bare int for unknown types on the DEVPROP path (construct Enum quirk)
#[derive(Debug, Clone)]
pub enum VType {
    Named(&'static str),
    NumStr(u32),
    Num(u32),
}

#[derive(Debug, Clone)]
pub enum VData {
    Str(String),
    Bytes(Vec<u8>),
    U32(u32),
    U64(u64),
    List(Vec<String>),
    /// Raw FILETIME; converted to datetime by the Python wrapper (so timestamp
    /// arithmetic matches regipy.utils.convert_wintime exactly).
    Filetime(u64),
}

#[derive(Debug, Clone)]
pub struct ParsedValue {
    pub name: String,
    pub vtype: VType,
    pub data: VData,
    pub is_corrupted: bool,
}

/// Result of enumerating a key's values: parsed prefix + optional fatal error
/// (same generator semantics as SubkeyList).
pub struct ValueList {
    pub values: Vec<ParsedValue>,
    pub error: Option<ParseError>,
}

/// Python: `stream.read(data_size)` at the data cell payload — clamped at EOF,
/// never bounded by the cell size.
fn raw_data<'a>(data: &'a [u8], vk: &VkHeader) -> Cow<'a, [u8]> {
    let start = REGF_HEADER_SIZE + 4 + vk.data_offset as usize;
    if start >= data.len() {
        return Cow::Borrowed(&[][..]);
    }
    let end = ((start as u64).saturating_add(vk.data_size as u64)).min(data.len() as u64) as usize;
    Cow::Borrowed(&data[start..end])
}

/// Reassemble a "big data" (db) value from its segments.
///
/// Note: the Python implementation seeks to the segment list *cell* (including
/// its size field) and accidentally consumes the cell size as a bogus first
/// segment offset, which reads zero bytes and self-corrects. This is the
/// intended behavior it converges to: iterate the real segment offsets.
pub fn read_big_data(data: &[u8], value_head: &[u8], data_size: u32) -> Result<Vec<u8>> {
    if value_head.len() < 8 {
        return Err(ParseError::Parsing("Truncated big-data (db) record".to_string()));
    }
    let num_segments = u16::from_le_bytes([value_head[2], value_head[3]]) as usize;
    let list_off = u32::from_le_bytes([value_head[4], value_head[5], value_head[6], value_head[7]]);
    let list_payload = REGF_HEADER_SIZE + 4 + list_off as usize;
    let mut remaining = data_size as usize;
    // data_size comes from disk and may be corrupt — cap the pre-allocation.
    let mut out = Vec::with_capacity(remaining.min(1 << 20));
    for i in 0..num_segments {
        if remaining == 0 {
            break;
        }
        let seg = u32_at(data, list_payload + 4 * i, "big-data segment offset")? as usize;
        let seg_payload = REGF_HEADER_SIZE + 4 + seg;
        if seg_payload >= data.len() {
            break;
        }
        let take = remaining.min(BIG_DATA_THRESHOLD as usize).min(data.len() - seg_payload);
        out.extend_from_slice(&data[seg_payload..seg_payload + take]);
        remaining -= take;
    }
    Ok(out)
}

/// regipy.utils.try_decode_binary — decode order and trimming quirks preserved.
/// String results are always trimmed to MAX_LEN (256); the raw-bytes fallback
/// is trimmed to `max_len`. (In Python the function's max_len parameter always
/// receives its default.)
pub fn try_decode_binary(data: &[u8], as_json: bool, trim_values: bool) -> VData {
    if let Some(s) = decode_utf16le_strict(data) {
        let s = s.trim_end_matches('\0');
        return VData::Str(if trim_values { truncate_chars(s, MAX_LEN) } else { s.to_string() });
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let s = s.trim_end_matches('\0');
        return VData::Str(if trim_values { truncate_chars(s, MAX_LEN) } else { s.to_string() });
    }
    if as_json {
        VData::Str(if trim_values { hex_lower_trimmed(data, MAX_LEN) } else { hex_lower(data) })
    } else {
        let end = if trim_values { data.len().min(MAX_LEN) } else { data.len() };
        VData::Bytes(data[..end].to_vec())
    }
}

/// GreedyRange(CString("utf-16-le")) then filter out empty strings.
pub fn greedy_utf16_cstrings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let mut units: Vec<u16> = Vec::new();
        let mut p = pos;
        let mut terminated = false;
        while p + 2 <= data.len() {
            let u = u16::from_le_bytes([data[p], data[p + 1]]);
            p += 2;
            if u == 0 {
                terminated = true;
                break;
            }
            units.push(u);
        }
        if !terminated {
            // EOF before the NUL terminator: construct raises and GreedyRange
            // discards the partial element.
            break;
        }
        match char::decode_utf16(units.iter().copied()).collect::<std::result::Result<String, _>>() {
            Ok(s) => {
                out.push(s);
                pos = p;
            }
            Err(_) => break,
        }
    }
    out.retain(|s| !s.is_empty());
    out
}

/// Decode a single value's data (Python: NKRecord.iter_values body).
/// Returns Ok(None) for value types Python skips (0x200000).
fn decode_value(
    data: &[u8],
    vk: &VkHeader,
    as_json: bool,
    trim_values: bool,
    max_len: usize,
) -> Result<Option<ParsedValue>> {
    let dt = vk.data_type;
    let (vtype, match_name): (VType, Option<&'static str>) = if dt > 0xFFFF_0000 {
        // DEVPROP structure: the actual registry type is in the low 16 bits.
        let low = dt & 0xFFFF;
        match value_type_name(low) {
            Some(n) => (VType::Named(n), Some(n)),
            None => (VType::Num(low), None),
        }
    } else if dt == 0x0020_0000 {
        // Unknown data type regipy skips entirely.
        return Ok(None);
    } else {
        match value_type_name(dt) {
            Some(n) => (VType::Named(n), Some(n)),
            None => (VType::NumStr(dt), None),
        }
    };

    let inline = vk.data_size >= 0x8000_0000;
    let inline_len = ((vk.data_size & 0x7FFF_FFFF) as usize).min(4);
    let inline_bytes = vk.data_offset.to_le_bytes();
    let inline_data = &inline_bytes[..inline_len];

    let vdata: VData = match match_name {
        Some("REG_SZ") | Some("REG_EXPAND_SZ") => {
            if inline {
                // Data is stored in the data_offset field itself.
                try_decode_binary(inline_data, as_json, trim_values)
            } else {
                let raw = raw_data(data, vk);
                if vk.data_size > BIG_DATA_THRESHOLD && raw.starts_with(b"db") {
                    let big = read_big_data(data, &raw, vk.data_size)?;
                    try_decode_binary(&big, as_json, trim_values)
                } else {
                    try_decode_binary(&raw, as_json, trim_values)
                }
            }
        }
        Some("REG_BINARY") | Some("REG_NONE") => {
            if inline {
                if trim_values {
                    VData::Str(hex_lower_trimmed(inline_data, max_len))
                } else {
                    VData::Bytes(inline_data.to_vec())
                }
            } else {
                let raw = raw_data(data, vk);
                if vk.data_size > BIG_DATA_THRESHOLD && raw.starts_with(b"db") {
                    let big = read_big_data(data, &raw, vk.data_size)?;
                    if as_json {
                        try_decode_binary(&big, true, trim_values)
                    } else {
                        VData::Bytes(big)
                    }
                } else if trim_values {
                    VData::Str(hex_lower_trimmed(&raw, max_len))
                } else {
                    VData::Bytes(raw.into_owned())
                }
            }
        }
        Some("REG_DWORD") => {
            if inline {
                VData::U32(vk.data_offset)
            } else {
                let raw = raw_data(data, vk);
                if raw.len() < 4 {
                    return Err(ParseError::Parsing("Truncated REG_DWORD data".to_string()));
                }
                VData::U32(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
            }
        }
        Some("REG_QWORD") => {
            if inline {
                // Python returns the raw data_offset field here as well.
                VData::U32(vk.data_offset)
            } else {
                let raw = raw_data(data, vk);
                if raw.len() < 8 {
                    return Err(ParseError::Parsing("Truncated REG_QWORD data".to_string()));
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&raw[..8]);
                VData::U64(u64::from_le_bytes(b))
            }
        }
        Some("REG_MULTI_SZ") => {
            if inline {
                VData::List(greedy_utf16_cstrings(inline_data))
            } else {
                let raw = raw_data(data, vk);
                if vk.data_size > BIG_DATA_THRESHOLD && raw.starts_with(b"db") {
                    let big = read_big_data(data, &raw, vk.data_size)?;
                    VData::List(greedy_utf16_cstrings(&big))
                } else {
                    VData::List(greedy_utf16_cstrings(&raw))
                }
            }
        }
        Some("REG_RESOURCE_LIST") | Some("REG_RESOURCE_REQUIREMENTS_LIST") => {
            let raw = raw_data(data, vk);
            if trim_values {
                VData::Str(hex_lower_trimmed(&raw, max_len))
            } else {
                VData::Bytes(raw.into_owned())
            }
        }
        Some("REG_FILETIME") => {
            let raw = raw_data(data, vk);
            if raw.len() < 8 {
                return Err(ParseError::Parsing("Truncated REG_FILETIME data".to_string()));
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&raw[..8]);
            VData::Filetime(u64::from_le_bytes(b))
        }
        // REG_DWORD_BIG_ENDIAN, REG_LINK, REG_FULL_RESOURCE_DESCRIPTOR and all
        // unknown types fall through to try_decode_binary, like Python.
        _ => {
            let raw = raw_data(data, vk);
            try_decode_binary(&raw, as_json, trim_values)
        }
    };

    Ok(Some(ParsedValue { name: vk.name.clone(), vtype, data: vdata, is_corrupted: false }))
}

/// Enumerate the values of `nk` (Python: NKRecord.iter_values).
pub fn list_values(hive: &Hive, nk: &NkRecord, as_json: bool, trim_values: bool, max_len: usize) -> ValueList {
    let data = &hive.data;
    let mut out = Vec::new();
    if nk.values_count == 0 {
        return ValueList { values: out, error: None };
    }
    // values_count comes from disk and may be corrupt — cap the pre-allocation.
    out.reserve((nk.values_count as usize).min(4096));
    let list_payload = REGF_HEADER_SIZE + 4 + nk.values_list_offset as usize;
    for i in 0..nk.values_count as usize {
        let vk_off = match u32_at(data, list_payload + 4 * i, "VK offset") {
            Ok(v) => v,
            Err(_) => {
                // Python: RegistryParsingException("Bad registry VK at ...")
                return ValueList {
                    values: out,
                    error: Some(ParseError::Parsing(format!("Bad registry VK at {}", list_payload + 4 * i))),
                };
            }
        };
        let vk_payload = REGF_HEADER_SIZE + 4 + vk_off as usize;
        let vk = match parse_vk(data, vk_payload) {
            Ok(v) => v,
            // Python: a corrupt VK record ends value iteration silently.
            Err(_) => return ValueList { values: out, error: None },
        };
        match decode_value(data, &vk, as_json, trim_values, max_len) {
            Ok(Some(v)) => out.push(v),
            Ok(None) => continue,
            Err(e) => return ValueList { values: out, error: Some(e) },
        }
    }
    ValueList { values: out, error: None }
}

// ─── Class name ──────────────────────────────────────────────────────────────

pub fn class_name(hive: &Hive, nk: &NkRecord) -> String {
    let start = REGF_HEADER_SIZE + 4 + nk.class_name_offset as usize;
    let data = &hive.data;
    if start >= data.len() {
        return String::new();
    }
    let end = (start + nk.class_name_size as usize).min(data.len());
    decode_utf16le_replace(&data[start..end])
}

// ─── Security (SK record, security descriptor, SIDs, ACLs) ──────────────────

pub struct AceFlags {
    pub value: u8,
}

pub struct AccessMask {
    pub value: u32,
}

pub struct Ace {
    pub ace_type: String,
    pub flags: AceFlags,
    pub access_mask: AccessMask,
    pub sid: String,
}

pub struct SecurityInfo {
    pub owner: String,
    pub group: String,
    pub dacl: Option<Vec<Ace>>,
    pub sacl: Option<Vec<Ace>>,
}

pub const ACE_FLAG_NAMES: [(&str, u8); 4] = [
    ("OBJECT_INHERIT_ACE", 0x1),
    ("CONTAINER_INHERIT_ACE", 0x2),
    ("NO_PROPAGATE_INHERIT_ACE", 0x4),
    ("INHERIT_ONLY_ACE", 0x8),
];

pub const ACCESS_MASK_NAMES: [(&str, u32); 11] = [
    ("DELETE", 0x0001_0000),
    ("READ_CONTROL", 0x0002_0000),
    ("WRITE_DAC", 0x0004_0000),
    ("WRITE_OWNER", 0x0008_0000),
    ("SYNCHRONIZE", 0x0010_0000),
    ("ACCESS_SYSTEM_SECURITY", 0x0100_0000),
    ("MAXIMUM_ALLOWED", 0x0200_0000),
    ("GENERIC_ALL", 0x1000_0000),
    ("GENERIC_EXECUTE", 0x2000_0000),
    ("GENERIC_WRITE", 0x4000_0000),
    ("GENERIC_READ", 0x8000_0000),
];

/// ACE type names per regipy.structs.ACE (note: 13 is intentionally unmapped
/// there, so it stringifies to "13").
fn ace_type_name(t: u8) -> String {
    let name = match t {
        0 => "ACCESS_ALLOWED",
        1 => "ACCESS_DENIED",
        2 => "SYSTEM_AUDIT",
        3 => "SYSTEM_ALARM",
        4 => "ACCESS_ALLOWED_COMPOUND",
        5 => "ACCESS_ALLOWED_OBJECT",
        6 => "ACCESS_DENIED_OBJECT",
        7 => "SYSTEM_AUDIT_OBJECT",
        8 => "SYSTEM_ALARM_OBJECT",
        9 => "ACCESS_ALLOWED_CALLBACK",
        10 => "ACCESS_DENIED_CALLBACK",
        11 => "ACCESS_ALLOWED_CALLBACK_OBJECT",
        12 => "ACCESS_DENIED_CALLBACK_OBJECT",
        14 => "SYSTEM_ALARM_CALLBACK",
        15 => "SYSTEM_AUDIT_CALLBACK_OBJECT",
        16 => "SYSTEM_ALARM_CALLBACK_OBJECT",
        other => return other.to_string(),
    };
    name.to_string()
}

/// Parse a SID at a file offset (Python: SID struct + convert_sid).
fn parse_sid_at(data: &[u8], off: usize) -> Result<String> {
    let revision = *slice_at(data, off, 1, "SID revision")?.first().unwrap();
    let count = *slice_at(data, off + 1, 1, "SID subauthority count")?.first().unwrap() as usize;
    let auth_raw = slice_at(data, off + 2, 6, "SID identifier authority")?;
    let mut auth: u64 = 0;
    for &b in auth_raw {
        auth = (auth << 8) | b as u64;
    }
    let mut subs = Vec::with_capacity(count);
    for i in 0..count {
        subs.push(u32_at(data, off + 8 + 4 * i, "SID subauthority")?.to_string());
    }
    Ok(format!("S-{}-{}-{}", revision, auth, subs.join("-")))
}

fn parse_acl_at(data: &[u8], off: usize) -> Result<Vec<Ace>> {
    let ace_count = u16_at(data, off + 4, "ACL ace count")? as usize;
    let mut aces = Vec::with_capacity(ace_count.min(4096));
    let mut pos = off + 8;
    for _ in 0..ace_count {
        let ace_type = *slice_at(data, pos, 1, "ACE type")?.first().unwrap();
        let flags = *slice_at(data, pos + 1, 1, "ACE flags")?.first().unwrap();
        let size = u16_at(data, pos + 2, "ACE size")? as usize;
        let access_mask = u32_at(data, pos + 4, "ACE access mask")?;
        if size < 8 {
            return Err(ParseError::Parsing(format!("Bad ACE size {size} at offset {pos}")));
        }
        // The SID is parsed out of the ACE's trailing bytes.
        need(data, pos + 8, size - 8, "ACE SID")?;
        let sid = parse_sid_at(data, pos + 8)?;
        aces.push(Ace {
            ace_type: ace_type_name(ace_type),
            flags: AceFlags { value: flags },
            access_mask: AccessMask { value: access_mask },
            sid,
        });
        pos += size;
    }
    Ok(aces)
}

/// Python: NKRecord.get_security_key_info.
pub fn security_info(hive: &Hive, nk: &NkRecord) -> Result<SecurityInfo> {
    let data = &hive.data;
    let sk_cell = REGF_HEADER_SIZE + nk.security_key_offset as usize;
    // SECURITY_KEY_v1_1: 4 unknown bytes (cell size), "sk" signature, 2 unknown,
    // prev/next offsets, reference count, sd size, then the security descriptor.
    if slice_at(data, sk_cell + 4, 2, "SK signature")? != b"sk" {
        return Err(ParseError::Parsing(format!("Bad SK signature at offset {sk_cell}")));
    }
    let sd_base = sk_cell + 24;
    // SECURITY_DESCRIPTOR (self-relative): offsets are relative to its start.
    let owner_off = u32_at(data, sd_base + 4, "SD owner offset")? as usize;
    let group_off = u32_at(data, sd_base + 8, "SD group offset")? as usize;
    let sacl_off = u32_at(data, sd_base + 12, "SD SACL offset")? as usize;
    let dacl_off = u32_at(data, sd_base + 16, "SD DACL offset")? as usize;

    let owner = parse_sid_at(data, sd_base + owner_off)?;
    let group = parse_sid_at(data, sd_base + group_off)?;
    let sacl = if sacl_off > 0 { Some(parse_acl_at(data, sd_base + sacl_off)?) } else { None };
    let dacl = if dacl_off > 0 { Some(parse_acl_at(data, sd_base + dacl_off)?) } else { None };
    Ok(SecurityInfo { owner, group, dacl, sacl })
}
