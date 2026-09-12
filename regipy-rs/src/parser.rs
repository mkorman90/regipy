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
    ParseError::Parsing(format!(
        "Read out of bounds at offset {offset} while reading {what}"
    ))
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
    Ok(u32::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
    ]))
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
    data.iter()
        .map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' })
        .collect()
}

#[inline]
fn utf16le_units(data: &[u8]) -> impl Iterator<Item = u16> + '_ {
    data.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
}

/// bytes.decode("utf-16-le", errors="replace")
pub fn decode_utf16le_replace(data: &[u8]) -> String {
    let mut s: String = char::decode_utf16(utf16le_units(data))
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .collect();
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
    char::decode_utf16(utf16le_units(data))
        .collect::<std::result::Result<String, _>>()
        .ok()
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

const FILETIME_EPOCH: CivilDateTime = CivilDateTime {
    year: 1601,
    month: 1,
    day: 1,
    hour: 0,
    minute: 0,
    second: 0,
    microsecond: 0,
};

/// Correctly-rounded x/10 as f64, matching Python's int/int true division.
/// (`x as f64 / 10.0` would round twice: once at the u64→f64 conversion and
/// once at the division.)
fn u64_div10_f64(x: u64) -> f64 {
    let n = (x as u128) << 63;
    let mut q = n / 10;
    if !n.is_multiple_of(10) {
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
    let file_name = decode_utf16le_replace(file_name_raw)
        .trim_end_matches('\0')
        .to_string();
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
                return Err(ParseError::Parsing(
                    "No allocated root cell found in first HBIN".to_string(),
                ));
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

fn parse_leaf_elements(
    data: &[u8],
    pos: usize,
    stride: usize,
    out: &mut Vec<NkRecord>,
) -> Result<()> {
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
    SubkeyList {
        subkeys: out,
        error,
    }
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
        return Err(ParseError::Parsing(format!(
            "Bad VK signature at offset {payload}"
        )));
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
    Ok(VkHeader {
        name_size,
        data_size,
        data_offset,
        data_type,
        flags,
        name,
    })
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
        return Err(ParseError::Parsing(
            "Truncated big-data (db) record".to_string(),
        ));
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
        let take = remaining
            .min(BIG_DATA_THRESHOLD as usize)
            .min(data.len() - seg_payload);
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
        return VData::Str(if trim_values {
            truncate_chars(s, MAX_LEN)
        } else {
            s.to_string()
        });
    }
    if let Ok(s) = std::str::from_utf8(data) {
        let s = s.trim_end_matches('\0');
        return VData::Str(if trim_values {
            truncate_chars(s, MAX_LEN)
        } else {
            s.to_string()
        });
    }
    if as_json {
        VData::Str(if trim_values {
            hex_lower_trimmed(data, MAX_LEN)
        } else {
            hex_lower(data)
        })
    } else {
        let end = if trim_values {
            data.len().min(MAX_LEN)
        } else {
            data.len()
        };
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
        match char::decode_utf16(units.iter().copied()).collect::<std::result::Result<String, _>>()
        {
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
                return Err(ParseError::Parsing(
                    "Truncated REG_FILETIME data".to_string(),
                ));
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

    Ok(Some(ParsedValue {
        name: vk.name.clone(),
        vtype,
        data: vdata,
        is_corrupted: false,
    }))
}

/// Enumerate the values of `nk` (Python: NKRecord.iter_values).
pub fn list_values(
    hive: &Hive,
    nk: &NkRecord,
    as_json: bool,
    trim_values: bool,
    max_len: usize,
) -> ValueList {
    let data = &hive.data;
    let mut out = Vec::new();
    if nk.values_count == 0 {
        return ValueList {
            values: out,
            error: None,
        };
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
                    error: Some(ParseError::Parsing(format!(
                        "Bad registry VK at {}",
                        list_payload + 4 * i
                    ))),
                };
            }
        };
        let vk_payload = REGF_HEADER_SIZE + 4 + vk_off as usize;
        let vk = match parse_vk(data, vk_payload) {
            Ok(v) => v,
            // Python: a corrupt VK record ends value iteration silently.
            Err(_) => {
                return ValueList {
                    values: out,
                    error: None,
                }
            }
        };
        match decode_value(data, &vk, as_json, trim_values, max_len) {
            Ok(Some(v)) => out.push(v),
            Ok(None) => continue,
            Err(e) => {
                return ValueList {
                    values: out,
                    error: Some(e),
                }
            }
        }
    }
    ValueList {
        values: out,
        error: None,
    }
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
    let count = *slice_at(data, off + 1, 1, "SID subauthority count")?
        .first()
        .unwrap() as usize;
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
            return Err(ParseError::Parsing(format!(
                "Bad ACE size {size} at offset {pos}"
            )));
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
        return Err(ParseError::Parsing(format!(
            "Bad SK signature at offset {sk_cell}"
        )));
    }
    let sd_base = sk_cell + 24;
    // SECURITY_DESCRIPTOR (self-relative): offsets are relative to its start.
    let owner_off = u32_at(data, sd_base + 4, "SD owner offset")? as usize;
    let group_off = u32_at(data, sd_base + 8, "SD group offset")? as usize;
    let sacl_off = u32_at(data, sd_base + 12, "SD SACL offset")? as usize;
    let dacl_off = u32_at(data, sd_base + 16, "SD DACL offset")? as usize;

    let owner = parse_sid_at(data, sd_base + owner_off)?;
    let group = parse_sid_at(data, sd_base + group_off)?;
    let sacl = if sacl_off > 0 {
        Some(parse_acl_at(data, sd_base + sacl_off)?)
    } else {
        None
    };
    let dacl = if dacl_off > 0 {
        Some(parse_acl_at(data, sd_base + dacl_off)?)
    } else {
        None
    };
    Ok(SecurityInfo {
        owner,
        group,
        dacl,
        sacl,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIV10_CASES: &[(u64, u64)] = &[
        (0, 0x0000000000000000),
        (1, 0x3fb999999999999a),
        (2, 0x3fc999999999999a),
        (3, 0x3fd3333333333333),
        (9, 0x3feccccccccccccd),
        (10, 0x3ff0000000000000),
        (11, 0x3ff199999999999a),
        (99, 0x4023cccccccccccd),
        (100, 0x4024000000000000),
        (999, 0x4058f9999999999a),
        (1000, 0x4059000000000000),
        (9007199254740990, 0x4309999999999998),
        (9007199254740991, 0x4309999999999999),
        (9007199254740992, 0x430999999999999a),
        (9007199254740993, 0x430999999999999a),
        (9007199254740994, 0x430999999999999b),
        (18014398509481983, 0x4319999999999999),
        (18014398509481984, 0x431999999999999a),
        (9223372036854775807, 0x43a999999999999a),
        (9223372036854775808, 0x43a999999999999a),
        (18446744073709551614, 0x43b999999999999a),
        (18446744073709551615, 0x43b999999999999a),
        (10000000000000000, 0x430c6bf526340000),
        (10000000000000000000, 0x43abc16d674ec800),
        (123456789012345678, 0x4345ee2a2eb5a5c4),
        (5000000000000001, 0x42fc6bf526340002),
        (9999999999999999, 0x430c6bf52633ffff),
        (2053695854357871005, 0x4386ccf4661c8dfb),
        (13679192365072849617, 0x43b2fbd34c4d70b6),
        (4517457392071889495, 0x439913b16ce8f687),
        (2574020394472462046, 0x438c93ce542db6ac),
        (1890702223848595625, 0x4384fdb2ec96d44d),
        (13662908291426823533, 0x43b2f60a452aec6b),
        (10060236952204337488, 0x43abec3a70fa7ac7),
        (10892664235628797826, 0x43ae3bb415047386),
        (586287033698423193, 0x436a094fd7c009d2),
        (1728372192399379054, 0x4383305448061a3c),
        (4291835990902352011, 0x4397d310d67cc9dd),
        (11105285438068160209, 0x43aed2c7a74d12fe),
        (10353144037217341363, 0x43acbc59ee015bd0),
        (13208230535885162025, 0x43b2548191b84a4d),
        (12937162279754847113, 0x43b1f4340e10a315),
        (7738774760351418614, 0x43a57abaedb58042),
        (8286444275301796832, 0x43a6ffdf6ed81629),
        (5131712758418120108, 0x439c7c9a39d5f0d9),
        (16035760590688802187, 0x43b6410bedfb1f15),
        (13997525239209781023, 0x43b36ceb8119c431),
        (2945194472877206461, 0x4390595f81ec1dab),
        (7795859673851708282, 0x43a5a34a9d23bea7),
        (5125821543982213238, 0x439c743b03bc7110),
        (3971837850219807024, 0x43960c5231431f00),
        (14083980817542670947, 0x43b38ba297e54dfe),
        (1885446857198079865, 0x4384eec32444ef40),
        (7008421793132065041, 0x43a373c87f6b260a),
        (6622000703604942743, 0x43a26136e93826e2),
        (6344863178936378387, 0x43a19c4be391caae),
        (4879548657232103939, 0x439b164175d76bea),
        (801519116549617023, 0x4371cc1bd2e43322),
        (8474893131606635472, 0x43a785c6148bc324),
        (2302636251494628997, 0x4389907c606dd1cc),
        (17013346644619304268, 0x43b79c5adcff4fd0),
        (1453607047024582931, 0x438023665380b94e),
        (5408184617760098545, 0x439e057e1a38876a),
        (11596357474505186610, 0x43b017da917ba1fd),
        (16333701732457992058, 0x43b6aae584c308bb),
        (6670988768861278913, 0x43a28405c9c5b82a),
        (3547098369942706623, 0x4393b0badea18557),
        (1283066103397798384, 0x437c7d62eaba3150),
        (12198155279199315353, 0x43b0eda7c2812c51),
        (14260593838171589262, 0x43b3ca61743908c1),
        (18174129289355940941, 0x43b938bf6e076888),
        (15777827095392894769, 0x43b5e56903ced7ba),
        (15983802509111602936, 0x43b62e965e9f8f38),
        (7012091250016467664, 0x43a37663f7d1f8a5),
        (8363943803604256569, 0x43a736f083db0841),
        (15386621650891716399, 0x43b55a6d16437939),
        (3000438492122948673, 0x4390a7e12a255bdb),
        (6553587738384543240, 0x43a2309aaa46273c),
        (12362549907685523630, 0x43b1280f5d38903a),
        (12946299709363366021, 0x43b1f773196d3c11),
        (12609228866373326921, 0x43b17fb2af4b2da9),
        (1317143838265288107, 0x437d3f188c3ca2a3),
        (11713281966713340531, 0x43b04164c9f5fe67),
        (9853141541719096833, 0x43ab5914016f298c),
        (4515964510634773972, 0x43991192517ddcd2),
        (8527195849335553775, 0x43a7aaefe3a1f759),
        (4979658421178727927, 0x439ba4852e26db32),
        (17070454183419799270, 0x43b7b0a4c37fbb57),
        (12694347471864137256, 0x43b19df02d439581),
        (4051184843001971257, 0x43967d1475d2a1b4),
        (5981960629525864751, 0x43a09a704cbca6fa),
        (14172883882709689509, 0x43b3ab3847af2d50),
        (1031873030137572921, 0x4376e984e2d77317),
        (15159582174570800377, 0x43b509c3f785dd17),
        (14850473871353034915, 0x43b49bf2bb00d25f),
        (7400184238106052604, 0x43a48a25abdcf382),
        (1220964237380856478, 0x437b1c60ced41111),
        (16844388258623453356, 0x43b76054300566b2),
        (10462625265789077476, 0x43ad0a2472fd13b5),
        (13243180843756265710, 0x43b260ec47fcd5c3),
        (3922267417137298135, 0x4395c5e092ed05e4),
        (9209191298904019989, 0x43a98f862387f55e),
        (16319523657909543376, 0x43b6a5dc07bd5403),
        (11858523945066023525, 0x43b074fe784a9cc7),
        (2635515642739380393, 0x438d429602c45f74),
        (2575724861012783070, 0x438c98a67dcfd8f3),
        (13742621121656847096, 0x43b3125c1c1fe9e6),
        (9942376124693992059, 0x43ab987bae83245d),
        (13779972549628856508, 0x43b31fa133d386b4),
        (7903209073802702201, 0x43a5ef915b1dee49),
        (10764282542738094197, 0x43ade07b96945e58),
        (6677655823134432407, 0x43a288c284ae0c9f),
        (18397413265700644792, 0x43b98812fd38d08a),
        (2551770246706798576, 0x438c54913732b21a),
        (9103760425370013864, 0x43a9449c5fe6e343),
        (13941720072365397720, 0x43b359180dcf2095),
        (15884545075369202069, 0x43b60b52f5679b2f),
        (2819424749284882229, 0x438f4d497f49a7f9),
        (2951146940301069764, 0x439061d500a6a686),
        (12552662823614133900, 0x43b16b9a087aad5f),
        (11001804832143224040, 0x43ae8940a4159d56),
        (7097704095687072272, 0x43a3b338da9cda45),
        (10992201237850606882, 0x43ae826dc1e056c3),
        (8633996433839738777, 0x43a7f6d2cd663390),
        (4637771848169556393, 0x4399beab91cfc804),
        (10205216524262217657, 0x43ac533e1264eb52),
        (17384780973582585581, 0x43b820509e62d601),
        (12549013897651186576, 0x43b16a4e2a4d180b),
        (2113106642663979449, 0x438775cf6fc6cdc8),
        (16321466152587137559, 0x43b6a68cb2f7da0f),
        (13851250634050167604, 0x43b338f3e80dbf17),
        (14178144042647201736, 0x43b3ad16b053a177),
        (6275129943002583699, 0x43a16abf7cba6ad1),
        (5414121733845069545, 0x439e0dee033e9f79),
        (2917495600126412442, 0x43903202b75fb84f),
        (59865493798337699, 0x433544bc25371faa),
        (13320247413671020492, 0x43b27c4d71e537ba),
        (13275765128541234669, 0x43b26c7fcdfcd264),
        (17928171007716980450, 0x43b8e15da786be25),
        (14055721717480188255, 0x43b381987173370b),
        (9365073917934051636, 0x43a9fe4905a2bf3a),
        (1962933219357751919, 0x4385cafde3ee1b2f),
        (11534752662811201046, 0x43b001f7a4afe2a1),
        (15526059072672948392, 0x43b58bf6d8bad716),
        (9364727264510620071, 0x43a9fe09f753ea0a),
        (3669262207937771719, 0x43945e55d0a4c230),
        (6897493091761027453, 0x43a324f6af3b067f),
        (2980053737230559329, 0x43908ae93be7ae5d),
        (17588965847757799010, 0x43b868db1ff43546),
        (17015905361960636559, 0x43b79d4393c72202),
        (16943214551238001182, 0x43b7837062f3fa20),
        (11048577505222294225, 0x43aeaa7c8a666de5),
        (9013184469153866811, 0x43a90440b443cbfa),
        (2063595287456017794, 0x4386e9172f373058),
        (6695813289279580209, 0x43a295a95795f848),
        (18175971244446575280, 0x43b93966f4634b97),
        (14882368366351747129, 0x43b4a74784954a67),
        (4417115578808483583, 0x439885194952b080),
        (4443296538731753242, 0x4398aa4ddd3921ac),
        (10465888220884581560, 0x43ad0c75fa2cf43f),
        (1452811136191383414, 0x43802123398ebc39),
        (13501312085701517929, 0x43b2bca12e4efe23),
        (15052972106611023585, 0x43b4e3e3d672d763),
        (18040629558683101512, 0x43b90951b334f8cb),
        (9826694299578192581, 0x43ab464947c08af7),
        (2319872024959105460, 0x4389c1790d69a495),
        (12170254566408733533, 0x43b0e3be3469afd4),
        (17466275249064254238, 0x43b83d447ad8f79c),
        (3046054765042593200, 0x4390e8b4449eb32c),
        (9733863205026578499, 0x43ab0453670d9226),
        (11189682723832186266, 0x43af0ebf6e2cab28),
        (17789355694006387871, 0x43b8b00c79a46ead),
        (17135429527665141793, 0x43b7c7ba3c9f05a4),
        (13932183773720301307, 0x43b355b4bb8dce55),
        (12725811749825856298, 0x43b1a91dd612afad),
        (13151587223000228575, 0x43b24061e3d1f310),
        (7360108821668995994, 0x43a46dabfedcc287),
        (12390437464425241534, 0x43b131f7b8ffe036),
        (6888392457627527310, 0x43a31e7f49ee12e2),
        (16594950762504082337, 0x43b707b5fabe6a55),
        (8328449353085606324, 0x43a71db81cb41992),
        (4573051503924355479, 0x439962b2720c640d),
        (1181069398379971535, 0x437a399a2d28d606),
        (388013639099795099, 0x43613b345114f5af),
        (10218048544868886114, 0x43ac5c5c33eaebe1),
        (10854804241263414419, 0x43ae20cd63a561c3),
        (132647652111166134, 0x4347901de9380223),
        (13057360759567981142, 0x43b21ee80b01d143),
        (1086029281467823798, 0x43781d5c9a9c198b),
        (1243316505448017364, 0x437b9b6fa390f97d),
        (579466799507675942, 0x4369bbc6594c1ebd),
        (6095329886943121601, 0x43a0eafe0c2c036a),
        (9484506392353289491, 0x43aa5325a99d3a57),
        (5136998843743592237, 0x439c841d4ae52bf3),
        (8954317038990532775, 0x43a8da6cc7ef0d3a),
        (9947110392639011130, 0x43ab9bd8d70af80b),
        (13343499577104216175, 0x43b284903783631e),
        (16277094700513352822, 0x43b696c92397f2fc),
        (10629228785065517402, 0x43ad808573ea0993),
        (4482507869643667449, 0x4398e206dcfd3396),
        (8724810724676522399, 0x43a83759d35b5f5d),
        (7508930986792984477, 0x43a4d76a96f624d3),
        (1740003900829643871, 0x43835163768d655d),
        (12156086182128678187, 0x43b0deb599027b3f),
        (6535636613594701523, 0x43a223d95fe2dead),
        (7583498532299974161, 0x43a50c6658e27cbb),
        (15934975371981548979, 0x43b61d3d913f27e5),
        (999281963395495706, 0x43763042a45dd458),
        (12054126087653924451, 0x43b0ba7c61913cf6),
        (11919912492747341904, 0x43b08acdb9cc6506),
        (1118106495833205230, 0x4378d3b318284fdd),
        (13433169699312644154, 0x43b2a46baabd81d2),
        (14768325111238658311, 0x43b47ec358224941),
        (2015657872592376414, 0x438660d81fe3aba8),
        (3534213002786500868, 0x43939e6b334ca994),
        (9892726009100339183, 0x43ab753460d689e8),
        (2585906988015179389, 0x438cb596f6c246ac),
        (3384756894773047137, 0x4392ca07629199c6),
        (8533981636164762649, 0x43a7afc23774a959),
        (16131418598117953727, 0x43b66307f9866522),
        (1390605763237061244, 0x437ee0adb7e091d1),
        (14905379553914455092, 0x43b4af745f8b581a),
        (15789802189125410791, 0x43b5e9aa24afa68a),
        (1806097268602969763, 0x43840d3cb7a3e819),
        (12029949924523334488, 0x43b0b1e59267b1f0),
        (9972087237154765269, 0x43abad9819fff698),
        (272234306624415600, 0x43582de4388cf296),
    ];

    #[test]
    fn div10_matches_cpython() {
        for &(x, expected_bits) in DIV10_CASES {
            let got = u64_div10_f64(x).to_bits();
            assert_eq!(got, expected_bits, "x = {x}");
        }
    }

    #[test]
    fn div10_is_monotone() {
        // x/10 is monotone; any inversion means a rounding bug.
        let mut prev = 0.0f64;
        let mut x: u64 = 0;
        for _ in 0..50_000 {
            x = x.wrapping_add(1_000_003); // strictly increasing, no wrap
            let v = u64_div10_f64(x);
            assert!(v >= prev, "not monotone at x = {x}");
            prev = v;
        }
    }

    #[test]
    fn ascii_replace_maps_high_bytes() {
        assert_eq!(decode_ascii_replace(b"abc"), "abc");
        assert_eq!(decode_ascii_replace(b"a\xffb\x80"), "a\u{FFFD}b\u{FFFD}");
        assert_eq!(decode_ascii_replace(b""), "");
    }

    #[test]
    fn utf16le_replace_handles_surrogates_and_odd_tail() {
        // "A" + lone high surrogate + "B"
        let data = [0x41, 0x00, 0x3D, 0xD8, 0x42, 0x00];
        assert_eq!(decode_utf16le_replace(&data), "A\u{FFFD}B");
        // Odd trailing byte -> single FFFD, like CPython.
        assert_eq!(decode_utf16le_replace(&[0x41, 0x00, 0x42]), "A\u{FFFD}");
        assert_eq!(decode_utf16le_replace(&[]), "");
    }

    #[test]
    fn utf16le_strict_rejects_bad_input() {
        assert_eq!(decode_utf16le_strict(&[0x41, 0x00]), Some("A".to_string()));
        assert_eq!(decode_utf16le_strict(&[0x41, 0x00, 0x42]), None); // odd length
        assert_eq!(decode_utf16le_strict(&[0x3D, 0xD8]), None); // lone surrogate
        assert_eq!(decode_utf16le_strict(&[]), Some(String::new()));
    }

    #[test]
    fn truncate_counts_code_points_not_bytes() {
        assert_eq!(truncate_chars("héllo wörld", 5), "héllo");
        assert_eq!(truncate_chars("abc", 10), "abc");
        assert_eq!(truncate_chars("", 3), "");
        // Emoji are single code points.
        assert_eq!(truncate_chars("a🙂b", 2), "a🙂");
    }

    #[test]
    fn hex_encoding_basics() {
        assert_eq!(hex_lower(&[0x00, 0xAB, 0xFF]), "00abff");
        assert_eq!(hex_lower(&[]), "");
        // Odd max_chars: encode just enough bytes, then truncate the string.
        assert_eq!(hex_lower_trimmed(&[0x12, 0x34, 0x56], 5), "12345");
        assert_eq!(hex_lower_trimmed(&[0x12, 0x34, 0x56], 6), "123456");
        assert_eq!(hex_lower_trimmed(&[0x12, 0x34, 0x56], 100), "123456");
    }

    #[test]
    fn filetime_known_values() {
        let epoch = filetime_to_civil(0);
        assert_eq!(
            epoch,
            CivilDateTime {
                year: 1601,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                microsecond: 0
            }
        );
        // 132223104000000000 == 2020-01-01T00:00:00Z (verified against CPython).
        let y2k20 = filetime_to_civil(132_223_104_000_000_000);
        assert_eq!(y2k20.year, 2020);
        assert_eq!((y2k20.month, y2k20.day), (1, 1));
        assert_eq!((y2k20.hour, y2k20.minute, y2k20.second), (0, 0, 0));
        assert_eq!(y2k20.microsecond, 0);
        // Overflow clamps to the epoch, like regipy.utils.convert_wintime.
        assert_eq!(filetime_to_civil(u64::MAX), epoch);
        // Fractional microseconds round half-to-even: 5 ticks = 0.5us -> 0.
        assert_eq!(filetime_to_civil(5).microsecond, 0);
        // 15 ticks = 1.5us -> 2 (ties away from the .5 go up).
        assert_eq!(filetime_to_civil(15).microsecond, 2);
    }

    #[test]
    fn civil_date_roundtrip() {
        for (y, m, d) in [
            (1601, 1, 1),
            (1970, 1, 1),
            (2000, 2, 29),
            (2026, 9, 12),
            (9999, 12, 31),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d));
        }
        // 1970-01-01 is day 0 by definition.
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn greedy_utf16_cstrings_skips_empties_and_partial_tail() {
        // "AB", "", "C", then an unterminated tail (dropped like construct).
        let data = b"A\x00B\x00\x00\x00\x00\x00C\x00\x00\x00D\x00";
        assert_eq!(greedy_utf16_cstrings(data), vec!["AB", "C"]);
        assert_eq!(greedy_utf16_cstrings(b""), Vec::<String>::new());
    }

    #[test]
    fn big_data_reassembly() {
        // Real big-data segments are BIG_DATA_THRESHOLD bytes except the last.
        let seg1 = vec![b'A'; BIG_DATA_THRESHOLD as usize];
        let seg2 = b"world";
        let total = seg1.len() + seg2.len();
        let list_off = 100u32;
        let seg1_off = 200u32;
        let seg2_off = seg1_off + BIG_DATA_THRESHOLD + 64;
        let mut data = vec![0u8; REGF_HEADER_SIZE + 4 + seg2_off as usize + 64];
        let list_payload = REGF_HEADER_SIZE + 4 + list_off as usize;
        data[list_payload..list_payload + 4].copy_from_slice(&seg1_off.to_le_bytes());
        data[list_payload + 4..list_payload + 8].copy_from_slice(&seg2_off.to_le_bytes());
        let p1 = REGF_HEADER_SIZE + 4 + seg1_off as usize;
        let p2 = REGF_HEADER_SIZE + 4 + seg2_off as usize;
        data[p1..p1 + seg1.len()].copy_from_slice(&seg1);
        data[p2..p2 + seg2.len()].copy_from_slice(seg2);

        let mut head = vec![0u8; 8];
        head[0..2].copy_from_slice(b"db");
        head[2..4].copy_from_slice(&2u16.to_le_bytes());
        head[4..8].copy_from_slice(&list_off.to_le_bytes());

        let out = read_big_data(&data, &head, total as u32).unwrap();
        let mut expected = seg1.clone();
        expected.extend_from_slice(seg2);
        assert_eq!(out, expected);
        // Truncated head is an error, not a panic.
        assert!(read_big_data(&data, &head[..4], total as u32).is_err());
    }

    #[test]
    fn try_decode_binary_prefers_utf16le_then_utf8_then_hex() {
        // Valid UTF-16LE with trailing NULs (trimmed).
        let utf16 = b"H\x00i\x00\x00\x00\x00\x00";
        assert!(matches!(
            try_decode_binary(utf16, false, true),
            VData::Str(ref s) if s == "Hi"
        ));
        // Odd length is never valid strict UTF-16LE; valid UTF-8 falls through.
        let utf8 = "héllo!".as_bytes(); // 7 bytes
        assert!(matches!(
            try_decode_binary(utf8, false, true),
            VData::Str(ref s) if s == "héllo!"
        ));
        // Neither: hex when as_json, raw bytes otherwise.
        let bin = &[0xFF, 0xFE, 0xFD];
        assert!(matches!(
            try_decode_binary(bin, true, false),
            VData::Str(ref s) if s == "fffefd"
        ));
        assert!(matches!(
            try_decode_binary(bin, false, false),
            VData::Bytes(ref b) if b == bin
        ));
        // trim_values caps strings at MAX_LEN code points. Odd byte length so
        // the strict UTF-16LE path fails and UTF-8 is exercised.
        let long = "x".repeat(MAX_LEN + 11);
        match try_decode_binary(long.as_bytes(), false, true) {
            VData::Str(s) => assert_eq!(s.chars().count(), MAX_LEN),
            other => panic!("expected Str, got {other:?}"),
        }
    }

    #[test]
    fn value_type_names_known() {
        assert_eq!(value_type_name(1), Some("REG_SZ"));
        assert_eq!(value_type_name(11), Some("REG_QWORD"));
        assert_eq!(value_type_name(16), Some("REG_FILETIME"));
        assert_eq!(value_type_name(0xBEEF), None);
    }
}
