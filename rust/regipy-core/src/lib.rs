//! POC REGF parser.
//!
//! Scope: REGF header, hbin/cell walk, NK/VK records, lf/lh/li/ri subkey lists.
//! Out of scope (POC): transaction logs, security descriptors, big data blocks
//! (we read them as raw bytes), DEVPROP, plugin layer.

use std::path::Path;
use thiserror::Error;

pub const REGF_HEADER_SIZE: usize = 4096;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad regf signature")]
    BadRegfSignature,
    #[error("bad hbin signature at offset {0:#x}")]
    BadHbinSignature(usize),
    #[error("unexpected eof at offset {0:#x} (need {1} bytes)")]
    Eof(usize, usize),
    #[error("unknown subkey list signature {0:?} at offset {1:#x}")]
    UnknownSubkeyList([u8; 2], usize),
    #[error("bad nk signature at offset {0:#x}")]
    BadNkSignature(usize),
    #[error("bad vk signature at offset {0:#x}")]
    BadVkSignature(usize),
}

pub type Result<T> = std::result::Result<T, Error>;

/// A loaded registry hive backed by mmap or a Vec.
pub struct Hive {
    backing: Backing,
    root_offset: u32,
}

// SAFETY: Hive is read-only after construction; both backings are Send+Sync.
unsafe impl Send for Hive {}
unsafe impl Sync for Hive {}

enum Backing {
    Mmap(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl AsRef<[u8]> for Backing {
    fn as_ref(&self) -> &[u8] {
        match self {
            Backing::Mmap(m) => &m[..],
            Backing::Owned(v) => &v[..],
        }
    }
}

impl Hive {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        // SAFETY: file is opened read-only; we do not modify it.
        let mmap = unsafe { memmap2::Mmap::map(&file)? };
        Self::from_backing(Backing::Mmap(mmap))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        Self::from_backing(Backing::Owned(bytes))
    }

    fn from_backing(backing: Backing) -> Result<Self> {
        let buf = backing.as_ref();
        if buf.len() < REGF_HEADER_SIZE {
            return Err(Error::Eof(0, REGF_HEADER_SIZE));
        }
        if &buf[0..4] != b"regf" {
            return Err(Error::BadRegfSignature);
        }
        let root_offset = read_u32(buf, 36)?;
        Ok(Self { backing, root_offset })
    }

    /// Parse the full REGF header.
    pub fn header(&self) -> RegfHeader {
        let buf = self.data();
        let primary_sequence_num = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let secondary_sequence_num = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let last_modification_time = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let major_version = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let minor_version = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let file_type = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        let file_format = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        let root_key_offset = u32::from_le_bytes(buf[36..40].try_into().unwrap());
        let hive_bins_data_size = u32::from_le_bytes(buf[40..44].try_into().unwrap());
        let clustering_factor = u32::from_le_bytes(buf[44..48].try_into().unwrap());
        // file_name: PaddedString(64, "utf-16-le") starting at offset 48
        let file_name_raw = &buf[48..48 + 64];
        let mut file_name = decode_utf16_le(file_name_raw);
        // PaddedString strips trailing NULs
        while file_name.ends_with('\u{0}') {
            file_name.pop();
        }
        // checksum at offset 4096-4 = 508 (after header struct + padding)
        // Actually: from regipy struct: header (48) + file_name (64) + padding (396) + checksum (4) = 512
        let checksum = u32::from_le_bytes(buf[508..512].try_into().unwrap());

        RegfHeader {
            primary_sequence_num,
            secondary_sequence_num,
            last_modification_time,
            major_version,
            minor_version,
            file_type,
            file_format,
            root_key_offset,
            hive_bins_data_size,
            clustering_factor,
            file_name,
            checksum,
        }
    }

    /// Find a key by path (case-insensitive). Path uses backslashes.
    /// Empty path or "\\" returns the root.
    pub fn get_key(&self, key_path: &str) -> Result<Option<NkRecord<'_>>> {
        let root = self.root()?;
        if key_path.is_empty() || key_path == "\\" {
            return Ok(Some(root));
        }
        // Strip a single leading backslash
        let p = key_path.strip_prefix('\\').unwrap_or(key_path);
        if p.is_empty() {
            return Ok(Some(root));
        }
        let parts: Vec<&str> = p.split('\\').filter(|s| !s.is_empty()).collect();
        let mut current = root;
        for part in parts {
            match current.get_subkey(part) {
                Some(sk) => current = sk,
                None => return Ok(None),
            }
        }
        Ok(Some(current))
    }

    fn data(&self) -> &[u8] {
        self.backing.as_ref()
    }

    /// Public access to the underlying byte buffer (for bindings/tools).
    pub fn bytes(&self) -> &[u8] {
        self.backing.as_ref()
    }

    pub fn root(&self) -> Result<NkRecord<'_>> {
        // root_offset is offset into hbin data; +4 to skip cell-size header
        let cell_data_offset = REGF_HEADER_SIZE + self.root_offset as usize + 4;
        NkRecord::parse_at(self.data(), cell_data_offset)
    }
}

/// Mirror of the construct-defined CM_KEY_NODE header for FFI.
#[derive(Debug, Clone)]
pub struct NkHeader {
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
    pub key_name_string: Vec<u8>,
}

/// REGF header fields. Mirrors `regipy.structs.REGF_HEADER`.
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

/// Parsed NK record. Holds a slice into the underlying hive.
pub struct NkRecord<'a> {
    data: &'a [u8],
    offset: usize, // start of "nk" signature
    pub flags: u16,
    pub last_modified: u64,
    pub subkey_count: u32,
    pub subkeys_list_offset: u32,
    pub values_count: u32,
    pub values_list_offset: u32,
    name_size: u16,
}

impl<'a> NkRecord<'a> {
    /// File-absolute offset of the "nk" signature.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// All fields of the NK header as a struct, useful for FFI.
    pub fn header_fields(&self) -> NkHeader {
        let body = &self.data[self.offset + 2..];
        NkHeader {
            flags: self.flags,
            last_modified: self.last_modified,
            access_bits: body[10..14].try_into().unwrap(),
            parent_key_offset: u32::from_le_bytes(body[14..18].try_into().unwrap()),
            subkey_count: self.subkey_count,
            volatile_subkey_count: u32::from_le_bytes(body[22..26].try_into().unwrap()),
            subkeys_list_offset: self.subkeys_list_offset,
            volatile_subkeys_list_offset: u32::from_le_bytes(body[30..34].try_into().unwrap()),
            values_count: self.values_count,
            values_list_offset: self.values_list_offset,
            security_key_offset: u32::from_le_bytes(body[42..46].try_into().unwrap()),
            class_name_offset: u32::from_le_bytes(body[46..50].try_into().unwrap()),
            largest_sk_name: u32::from_le_bytes(body[50..54].try_into().unwrap()),
            largest_sk_class_name: u32::from_le_bytes(body[54..58].try_into().unwrap()),
            largest_value_name: u32::from_le_bytes(body[58..62].try_into().unwrap()),
            largest_value_data: u32::from_le_bytes(body[62..66].try_into().unwrap()),
            key_name_size: self.name_size,
            class_name_size: u16::from_le_bytes([body[72], body[73]]),
            key_name_string: self.raw_name().to_vec(),
        }
    }

    /// Raw bytes of the key name (not yet decoded).
    pub fn raw_name(&self) -> &'a [u8] {
        let name_start = self.offset + 2 + 74;
        let name_end = name_start + self.name_size as usize;
        if name_end > self.data.len() {
            return &[];
        }
        &self.data[name_start..name_end]
    }

    /// Class name string, decoded as UTF-16LE.
    pub fn class_name(&self) -> String {
        let body = &self.data[self.offset + 2..];
        let class_name_offset = u32::from_le_bytes(body[46..50].try_into().unwrap());
        let class_name_size = u16::from_le_bytes([body[72], body[73]]) as usize;
        if class_name_offset == 0xFFFF_FFFF || class_name_size == 0 {
            return String::new();
        }
        let start = REGF_HEADER_SIZE + class_name_offset as usize + 4;
        let end = start + class_name_size;
        if end > self.data.len() {
            return String::new();
        }
        decode_utf16_le(&self.data[start..end])
    }

    /// Find a direct subkey by case-insensitive name match.
    pub fn get_subkey(&self, name: &str) -> Option<NkRecord<'a>> {
        if self.subkey_count == 0 {
            return None;
        }
        let want = name.to_ascii_lowercase();
        for sk in self.iter_subkeys() {
            let sk_name = sk.name();
            if sk_name.to_ascii_lowercase() == want {
                return Some(sk);
            }
        }
        None
    }

    pub fn parse_at(data: &'a [u8], offset: usize) -> Result<Self> {
        // offset points to the "nk" signature (2 bytes), then the fixed 74-byte body
        if data.len() < offset + 2 + 74 {
            return Err(Error::Eof(offset, 2 + 74));
        }
        if &data[offset..offset + 2] != b"nk" {
            return Err(Error::BadNkSignature(offset));
        }
        let body = &data[offset + 2..];
        let flags = u16::from_le_bytes([body[0], body[1]]);
        let last_modified = u64::from_le_bytes(body[2..10].try_into().unwrap());
        // body[10..14] access_bits, body[14..18] parent_key_offset
        let subkey_count = u32::from_le_bytes(body[18..22].try_into().unwrap());
        // body[22..26] volatile_subkey_count
        let subkeys_list_offset = u32::from_le_bytes(body[26..30].try_into().unwrap());
        // body[30..34] volatile_subkeys_list_offset
        let values_count = u32::from_le_bytes(body[34..38].try_into().unwrap());
        let values_list_offset = u32::from_le_bytes(body[38..42].try_into().unwrap());
        // body[42..46] security_key_offset
        // body[46..50] class_name_offset
        // body[50..54] largest_sk_name
        // body[54..58] largest_sk_class_name
        // body[58..62] largest_value_name
        // body[62..66] largest_value_data
        // body[66..70] unknown
        let name_size = u16::from_le_bytes([body[70], body[71]]);
        // body[72..74] class_name_size

        Ok(Self {
            data,
            offset,
            flags,
            last_modified,
            subkey_count,
            subkeys_list_offset,
            values_count,
            values_list_offset,
            name_size,
        })
    }

    /// Decoded key name. Returns owned String because of optional UTF-16 decode.
    pub fn name(&self) -> String {
        let name_start = self.offset + 2 + 74;
        let name_end = name_start + self.name_size as usize;
        if name_end > self.data.len() {
            return String::new();
        }
        let raw = &self.data[name_start..name_end];
        // KEY_COMP_NAME = 0x0020 — ASCII; otherwise UTF-16 LE.
        if self.flags & 0x0020 != 0 {
            String::from_utf8_lossy(raw).into_owned()
        } else {
            decode_utf16_le(raw)
        }
    }

    /// Iterator over subkey NK records.
    pub fn iter_subkeys(&self) -> SubkeyIter<'a> {
        if self.subkey_count == 0 {
            return SubkeyIter::empty(self.data);
        }
        // +4 to skip the cell-size header
        let target = REGF_HEADER_SIZE + self.subkeys_list_offset as usize + 4;
        SubkeyIter::new(self.data, target)
    }

    /// Iterator over the subkey's values.
    pub fn iter_values(&self) -> ValueIter<'a> {
        if self.values_count == 0 {
            return ValueIter::empty(self.data);
        }
        let target = REGF_HEADER_SIZE + self.values_list_offset as usize + 4;
        ValueIter::new(self.data, target, self.values_count as usize)
    }
}

/// Yields NK records from an lf/lh/li/ri-rooted subkey list.
pub struct SubkeyIter<'a> {
    data: &'a [u8],
    /// Pending list of NK offsets (file-absolute, starting at "nk" sig)
    queue: Vec<usize>,
    /// Position in queue
    pos: usize,
}

impl<'a> SubkeyIter<'a> {
    fn empty(data: &'a [u8]) -> Self {
        Self { data, queue: Vec::new(), pos: 0 }
    }

    fn new(data: &'a [u8], list_offset: usize) -> Self {
        let mut iter = Self::empty(data);
        if let Err(_) = iter.expand(list_offset) {
            // Swallow errors in iterator construction; iteration will be empty
            iter.queue.clear();
        }
        iter
    }

    fn expand(&mut self, list_offset: usize) -> Result<()> {
        if list_offset + 4 > self.data.len() {
            return Err(Error::Eof(list_offset, 4));
        }
        let sig = [self.data[list_offset], self.data[list_offset + 1]];
        let count = u16::from_le_bytes([self.data[list_offset + 2], self.data[list_offset + 3]]) as usize;
        let elements_start = list_offset + 4;

        match &sig {
            b"lf" | b"lh" => {
                // Each element: 4-byte key_node_offset, 4-byte hash/hint
                let need = count * 8;
                if elements_start + need > self.data.len() {
                    return Err(Error::Eof(elements_start, need));
                }
                self.queue.reserve(count);
                for i in 0..count {
                    let off = elements_start + i * 8;
                    let key_node_offset = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
                    // The element points to a CELL (cell-size header, then "nk" sig).
                    // To get to "nk" sig we skip 4 bytes for cell size.
                    let nk_off = REGF_HEADER_SIZE + key_node_offset as usize + 4;
                    self.queue.push(nk_off);
                }
            }
            b"li" => {
                // Each element: 4-byte key_node_offset
                let need = count * 4;
                if elements_start + need > self.data.len() {
                    return Err(Error::Eof(elements_start, need));
                }
                self.queue.reserve(count);
                for i in 0..count {
                    let off = elements_start + i * 4;
                    let key_node_offset = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
                    let nk_off = REGF_HEADER_SIZE + key_node_offset as usize + 4;
                    self.queue.push(nk_off);
                }
            }
            b"ri" => {
                // Each element: 4-byte subkey_list_offset (recurse into another list)
                let need = count * 4;
                if elements_start + need > self.data.len() {
                    return Err(Error::Eof(elements_start, need));
                }
                for i in 0..count {
                    let off = elements_start + i * 4;
                    let sub_list_offset = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
                    let target = REGF_HEADER_SIZE + sub_list_offset as usize + 4;
                    self.expand(target)?;
                }
            }
            _ => return Err(Error::UnknownSubkeyList(sig, list_offset)),
        }
        Ok(())
    }
}

impl<'a> Iterator for SubkeyIter<'a> {
    type Item = NkRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.queue.len() {
            let off = self.queue[self.pos];
            self.pos += 1;
            match NkRecord::parse_at(self.data, off) {
                Ok(nk) => return Some(nk),
                Err(_) => continue, // skip corrupted
            }
        }
        None
    }
}

/// Iterator over VK records of an NK.
pub struct ValueIter<'a> {
    data: &'a [u8],
    list_offset: usize,
    count: usize,
    idx: usize,
}

impl<'a> ValueIter<'a> {
    fn empty(data: &'a [u8]) -> Self {
        Self { data, list_offset: 0, count: 0, idx: 0 }
    }

    fn new(data: &'a [u8], list_offset: usize, count: usize) -> Self {
        Self { data, list_offset, count, idx: 0 }
    }
}

impl<'a> Iterator for ValueIter<'a> {
    type Item = VkRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.count {
            let entry_off = self.list_offset + self.idx * 4;
            self.idx += 1;
            if entry_off + 4 > self.data.len() {
                return None;
            }
            let vk_offset = u32::from_le_bytes(self.data[entry_off..entry_off + 4].try_into().unwrap());
            let vk_at = REGF_HEADER_SIZE + vk_offset as usize + 4;
            match VkRecord::parse_at(self.data, vk_at) {
                Ok(vk) => return Some(vk),
                Err(_) => continue,
            }
        }
        None
    }
}

pub struct VkRecord<'a> {
    data: &'a [u8],
    offset: usize, // start of "vk" sig
    pub name_size: u16,
    pub data_size: u32,
    pub data_offset: u32,
    pub data_type: u32,
    pub flags: u16,
}

/// Windows registry value types, matching `regipy.structs.VALUE_TYPE_ENUM`.
pub mod value_type {
    pub const REG_NONE: u32 = 0;
    pub const REG_SZ: u32 = 1;
    pub const REG_EXPAND_SZ: u32 = 2;
    pub const REG_BINARY: u32 = 3;
    pub const REG_DWORD: u32 = 4;
    pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
    pub const REG_LINK: u32 = 6;
    pub const REG_MULTI_SZ: u32 = 7;
    pub const REG_RESOURCE_LIST: u32 = 8;
    pub const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;
    pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;
    pub const REG_QWORD: u32 = 11;
    pub const REG_FILETIME: u32 = 16;
}

pub fn value_type_name(t: u32) -> &'static str {
    use value_type::*;
    match t {
        REG_NONE => "REG_NONE",
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        REG_DWORD_BIG_ENDIAN => "REG_DWORD_BIG_ENDIAN",
        REG_LINK => "REG_LINK",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_RESOURCE_LIST => "REG_RESOURCE_LIST",
        REG_FULL_RESOURCE_DESCRIPTOR => "REG_FULL_RESOURCE_DESCRIPTOR",
        REG_RESOURCE_REQUIREMENTS_LIST => "REG_RESOURCE_REQUIREMENTS_LIST",
        REG_QWORD => "REG_QWORD",
        REG_FILETIME => "REG_FILETIME",
        _ => "UNKNOWN",
    }
}

/// A decoded value, type-aware. Closer to regipy's Value dataclass.
#[derive(Debug, Clone)]
pub enum DecodedValue {
    None,
    String(String),
    ExpandString(String),
    Binary(Vec<u8>),
    Dword(u32),
    DwordBE(u32),
    Link(String),
    MultiString(Vec<String>),
    Qword(u64),
    /// Raw u64 wintime value; conversion to datetime happens in Python.
    Filetime(u64),
    /// Catch-all: raw bytes for types we don't decode (resource lists, etc.).
    Raw(Vec<u8>),
}

impl DecodedValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            DecodedValue::None => "REG_NONE",
            DecodedValue::String(_) => "REG_SZ",
            DecodedValue::ExpandString(_) => "REG_EXPAND_SZ",
            DecodedValue::Binary(_) => "REG_BINARY",
            DecodedValue::Dword(_) => "REG_DWORD",
            DecodedValue::DwordBE(_) => "REG_DWORD_BIG_ENDIAN",
            DecodedValue::Link(_) => "REG_LINK",
            DecodedValue::MultiString(_) => "REG_MULTI_SZ",
            DecodedValue::Qword(_) => "REG_QWORD",
            DecodedValue::Filetime(_) => "REG_FILETIME",
            DecodedValue::Raw(_) => "REG_BINARY",
        }
    }
}

impl<'a> VkRecord<'a> {
    fn parse_at(data: &'a [u8], offset: usize) -> Result<Self> {
        if data.len() < offset + 2 + 18 {
            return Err(Error::Eof(offset, 20));
        }
        if &data[offset..offset + 2] != b"vk" {
            return Err(Error::BadVkSignature(offset));
        }
        let body = &data[offset + 2..];
        let name_size = u16::from_le_bytes([body[0], body[1]]);
        let data_size = u32::from_le_bytes(body[2..6].try_into().unwrap());
        let data_offset = u32::from_le_bytes(body[6..10].try_into().unwrap());
        let data_type = u32::from_le_bytes(body[10..14].try_into().unwrap());
        let flags = u16::from_le_bytes([body[14], body[15]]);
        // body[16..18] padding
        Ok(Self {
            data,
            offset,
            name_size,
            data_size,
            data_offset,
            data_type,
            flags,
        })
    }

    pub fn name(&self) -> String {
        if self.name_size == 0 {
            return String::from("(default)");
        }
        let name_start = self.offset + 2 + 18;
        let name_end = name_start + self.name_size as usize;
        if name_end > self.data.len() {
            return String::new();
        }
        let raw = &self.data[name_start..name_end];
        // VALUE_COMP_NAME = 0x0001 — ASCII
        if self.flags & 0x0001 != 0 {
            String::from_utf8_lossy(raw).into_owned()
        } else {
            decode_utf16_le(raw)
        }
    }

    /// Raw value bytes (does not interpret type).
    pub fn raw_value(&self) -> &'a [u8] {
        // If high bit of data_size is set, value is stored inline in data_offset (4 bytes)
        if self.data_size & 0x8000_0000 != 0 {
            // Return a slice into the vk record itself (the data_offset field's bytes)
            let start = self.offset + 2 + 2 + 4; // sig + name_size + data_size -> data_offset bytes
            let actual_size = (self.data_size & 0x7FFF_FFFF) as usize;
            let actual_size = actual_size.min(4);
            if start + actual_size > self.data.len() {
                return &[];
            }
            return &self.data[start..start + actual_size];
        }
        let start = REGF_HEADER_SIZE + self.data_offset as usize + 4;
        let end = start + self.data_size as usize;
        if end > self.data.len() {
            return &[];
        }
        &self.data[start..end]
    }

    /// Whether the value data is stored inline in the data_offset field
    /// (the high bit of data_size is set).
    pub fn is_inline(&self) -> bool {
        self.data_size & 0x8000_0000 != 0
    }

    /// Returns the data bytes for this value as Python regipy would see them
    /// when calling `stream.read(data_size)` after seeking to the data offset.
    /// `reassemble_db` controls whether big-data ('db') block reassembly is
    /// done. Python regipy only reassembles for REG_SZ/REG_EXPAND_SZ and
    /// REG_BINARY/REG_NONE — for parity, callers pass `reassemble_db=true`
    /// only for those types.
    pub fn data_bytes(&self, reassemble_db: bool) -> std::borrow::Cow<'a, [u8]> {
        let cell_data_start = REGF_HEADER_SIZE + self.data_offset as usize + 4;

        if reassemble_db
            && self.data_size > 0x3FD8
            && cell_data_start + 2 <= self.data.len()
            && &self.data[cell_data_start..cell_data_start + 2] == b"db"
        {
            return std::borrow::Cow::Owned(self.reassemble_big_data());
        }

        if self.is_inline() {
            // Match Python: stream.read(0x80000000) on a BytesIO reads to EOF
            // from the seek point (REGF_HEADER_SIZE + 4 + data_offset).
            if cell_data_start >= self.data.len() {
                return std::borrow::Cow::Borrowed(&[]);
            }
            return std::borrow::Cow::Borrowed(&self.data[cell_data_start..]);
        }

        std::borrow::Cow::Borrowed(self.raw_value())
    }

    /// Reassemble a `db` big-data block. Returns the concatenated bytes.
    fn reassemble_big_data(&self) -> Vec<u8> {
        // Layout of `db` cell content (starts at cell_data_start, after cell-size header):
        //   "db" (2) + number_of_segments (u16) + offset_to_list_of_segments (u32)
        let cell_data_start = REGF_HEADER_SIZE + self.data_offset as usize + 4;
        if cell_data_start + 8 > self.data.len() {
            return Vec::new();
        }
        let _num_segments = u16::from_le_bytes(
            self.data[cell_data_start + 2..cell_data_start + 4].try_into().unwrap(),
        );
        let list_offset = u32::from_le_bytes(
            self.data[cell_data_start + 4..cell_data_start + 8].try_into().unwrap(),
        ) as usize;
        // The segment list is itself a cell — skip 4 bytes for cell-size header.
        let list_start = REGF_HEADER_SIZE + list_offset + 4;

        let mut buffer = Vec::with_capacity(self.data_size as usize);
        let mut remaining = self.data_size as usize;
        let mut cursor = list_start;
        const SEGMENT_SIZE: usize = 0x3FD8;

        while remaining > 0 {
            if cursor + 4 > self.data.len() {
                break;
            }
            let segment_offset =
                u32::from_le_bytes(self.data[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4;
            let seg_start = REGF_HEADER_SIZE + segment_offset + 4;
            let take = remaining.min(SEGMENT_SIZE);
            if seg_start + take > self.data.len() {
                break;
            }
            buffer.extend_from_slice(&self.data[seg_start..seg_start + take]);
            remaining = remaining.saturating_sub(take);
        }
        buffer
    }

    /// Type-aware decode of this value's data, parameterized to match
    /// `iter_values(as_json, trim_values)` in regipy.
    pub fn decode(&self) -> DecodedValue {
        self.decode_with(true, true)
    }

    pub fn decode_with(&self, as_json: bool, trim_values: bool) -> DecodedValue {
        // DEVPROP fallback: per regipy, types > 0xFFFF0000 strip the high half.
        let mut data_type = self.data_type;
        if data_type > 0xFFFF_0000 {
            data_type &= 0xFFFF;
        }

        let inline = self.is_inline();

        // Match regipy's inline-quirk: when high bit of data_size is set,
        // these types return data_offset directly (as an integer-valued
        // pseudo-value matching Python's behavior).
        if inline {
            match data_type {
                value_type::REG_SZ
                | value_type::REG_EXPAND_SZ
                | value_type::REG_BINARY
                | value_type::REG_NONE => {
                    return DecodedValue::Dword(self.data_offset);
                }
                value_type::REG_DWORD => {
                    return DecodedValue::Dword(self.data_offset);
                }
                value_type::REG_QWORD => {
                    return DecodedValue::Qword(self.data_offset as u64);
                }
                _ => {
                    // Fall through: REG_LINK, REG_DWORD_BIG_ENDIAN,
                    // REG_MULTI_SZ, REG_FILETIME, REG_RESOURCE_*, others —
                    // Python parses from value.value which (with huge size)
                    // contains rest-of-file.
                }
            }
        }

        // Python regipy only reassembles big-data blocks for REG_SZ/REG_EXPAND_SZ
        // and REG_BINARY/REG_NONE. Other types see the raw db-cell bytes.
        let reassemble_db = matches!(
            data_type,
            value_type::REG_SZ
                | value_type::REG_EXPAND_SZ
                | value_type::REG_BINARY
                | value_type::REG_NONE
        );
        let bytes = self.data_bytes(reassemble_db);
        let max_len = 256; // matches MAX_LEN in regipy.utils

        match data_type {
            value_type::REG_DWORD => {
                let v = if bytes.len() >= 4 {
                    u32::from_le_bytes(bytes[..4].try_into().unwrap())
                } else {
                    0
                };
                DecodedValue::Dword(v)
            }
            value_type::REG_QWORD => {
                let v = if bytes.len() >= 8 {
                    u64::from_le_bytes(bytes[..8].try_into().unwrap())
                } else {
                    0
                };
                DecodedValue::Qword(v)
            }
            value_type::REG_MULTI_SZ => DecodedValue::MultiString(decode_multi_sz(&bytes)),
            value_type::REG_FILETIME => {
                let v = if bytes.len() >= 8 {
                    u64::from_le_bytes(bytes[..8].try_into().unwrap())
                } else {
                    0
                };
                DecodedValue::Filetime(v)
            }
            // SZ-ish: regipy calls try_decode_binary on the bytes
            value_type::REG_SZ | value_type::REG_EXPAND_SZ => {
                match try_decode_binary(&bytes, as_json, trim_values, max_len) {
                    Ok(s) => DecodedValue::String(s),
                    Err(b) => DecodedValue::Binary(b),
                }
            }
            // BINARY/NONE: hex-encode-and-trim (or raw bytes)
            value_type::REG_BINARY | value_type::REG_NONE => {
                if trim_values {
                    let mut s = hex_encode(&bytes);
                    s = trim_to_chars(&s, max_len);
                    DecodedValue::String(s)
                } else {
                    DecodedValue::Binary(bytes.into_owned())
                }
            }
            // RESOURCE_*: hex-encode-and-trim (or raw)
            value_type::REG_RESOURCE_REQUIREMENTS_LIST | value_type::REG_RESOURCE_LIST => {
                if trim_values {
                    let mut s = hex_encode(&bytes);
                    s = trim_to_chars(&s, max_len);
                    DecodedValue::String(s)
                } else {
                    DecodedValue::Binary(bytes.into_owned())
                }
            }
            // REG_LINK, REG_DWORD_BIG_ENDIAN, REG_FULL_RESOURCE_DESCRIPTOR,
            // unknown: fall through to try_decode_binary (Python's else branch).
            _ => match try_decode_binary(&bytes, as_json, trim_values, max_len) {
                Ok(s) => DecodedValue::String(s),
                Err(b) => DecodedValue::Binary(b),
            },
        }
    }
}

/// Mirrors regipy.utils.try_decode_binary exactly.
///
/// ```python
/// def try_decode_binary(data, as_json=False, max_len=MAX_LEN, trim_values=True):
///     try:
///         value = data.decode("utf-16-le").rstrip("\x00")
///     except UnicodeDecodeError:
///         try:
///             value = data.decode().rstrip("\x00")
///         except Exception as ex:
///             value = binascii.b2a_hex(data).decode() if as_json else data
///     if trim_values:
///         value = value[:max_len]
///     return value
/// ```
///
/// Returns a String when one of the decode steps succeeded or the hex
/// fallback applies (always when `as_json=true`). When `as_json=false` and
/// both UTF decodes fail, returns the raw bytes via `Err`.
pub fn try_decode_binary(data: &[u8], as_json: bool, trim_values: bool, max_len: usize) -> std::result::Result<String, Vec<u8>> {
    // Step 1: strict UTF-16-LE
    if data.len() % 2 == 0 {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&units) {
            let mut s = s.trim_end_matches('\u{0}').to_string();
            if trim_values {
                s = trim_to_chars(&s, max_len);
            }
            return Ok(s);
        }
    }
    // Step 2: strict UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        let mut s = s.trim_end_matches('\u{0}').to_string();
        if trim_values {
            s = trim_to_chars(&s, max_len);
        }
        return Ok(s);
    }
    // Step 3: hex (when as_json) or raw bytes
    if as_json {
        let mut s = hex_encode(data);
        if trim_values {
            s = trim_to_chars(&s, max_len);
        }
        return Ok(s);
    }
    Err(data.to_vec())
}

/// Hex-encode lowercase, no separator (matches binascii.b2a_hex).
fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0F));
    }
    out
}

#[inline]
fn hex_digit(n: u8) -> char {
    if n < 10 {
        (b'0' + n) as char
    } else {
        (b'a' + n - 10) as char
    }
}

/// Match Python's `s[:max_len]` (Unicode chars, not bytes).
fn trim_to_chars(s: &str, max_len: usize) -> String {
    s.chars().take(max_len).collect()
}

/// Decode REG_MULTI_SZ matching `GreedyRange(CString("utf-16-le"))` exactly.
///
/// Construct's CString:
///   - Reads UTF-16-LE units until a NUL u16 terminator.
///   - Decodes the buffer with **strict** UTF-16; on UnicodeDecodeError,
///     CString raises StringError (a ConstructError).
///
/// GreedyRange catches ConstructError and stops iteration at that point.
/// So if any entry contains an unpaired surrogate, parsing stops there
/// (subsequent entries are not emitted, even if their bytes would decode).
///
/// regipy then post-filters empty strings: `[x for x in parsed if x]`.
fn decode_multi_sz(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf: Vec<u16> = Vec::new();
    for c in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([c[0], c[1]]);
        if u == 0 {
            // Strict UTF-16 decode: stop iteration if any unit is an
            // unpaired surrogate or otherwise invalid.
            match String::from_utf16(&buf) {
                Ok(s) => out.push(s),
                Err(_) => break, // mirror GreedyRange catching ConstructError
            }
            buf.clear();
        } else {
            buf.push(u);
        }
    }
    // Trailing run with no NUL is dropped.
    // Post-filter empty strings (matches regipy's post-processing).
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

/// Convert FILETIME (100ns ticks) to microseconds, matching Python's
/// `timedelta(microseconds=wintime/10)` exactly.
///
/// Python's `int / int` performs correctly-rounded multi-precision division
/// to produce the closest f64 of the exact rational `wintime/10`, then
/// `timedelta` normalizes that float to an integer via round-half-to-even.
///
/// In the IEEE 754 f64 range that FILETIME values land in (≈1.3e16),
/// representable values are spaced by 2 (only even integers fit). The exact
/// rational `q + r/10` (where `wintime = 10q + r`, `0 ≤ r ≤ 9`) is closest
/// to:
///   - `q`     when `q` is even (always wins by ≤1 vs. any odd-step neighbor)
///   - `q + 1` when `q` is odd and `r > 0` (q+1 is the nearest even integer)
///   - tie     when `q` is odd and `r = 0` (q-1 and q+1 are both at distance 1)
///
/// For the tie case we delegate to f64 round-to-nearest-even semantics by
/// converting q through f64 — that picks whichever side has the even
/// mantissa LSB, exactly as Python's `int → float` conversion does.
fn wintime_to_us(wintime: u64) -> i64 {
    let q = wintime / 10;
    let r = wintime % 10;
    if r == 0 {
        // Closest f64 to exactly q (no fractional part); IEEE handles ties.
        return (q as f64) as i64;
    }
    if q % 2 == 0 {
        q as i64
    } else {
        (q + 1) as i64
    }
}

/// Format a Windows FILETIME (100-ns ticks since 1601-01-01 UTC) as an
/// ISO 8601 datetime string with `+00:00` suffix, exactly matching
/// `regipy.utils.convert_wintime(wintime, as_json=True)`.
pub fn wintime_to_iso(wintime: u64) -> String {
    let total_us: i64 = wintime_to_us(wintime);
    let secs = total_us.div_euclid(1_000_000);
    let micros = total_us.rem_euclid(1_000_000) as u32;

    // Days from 1601-01-01 to 1970-01-01 = 134774
    const EPOCH_OFFSET_SECS: i64 = 134774 * 86400;
    let unix_secs = secs - EPOCH_OFFSET_SECS;

    // Compute civil date from unix_secs (UTC). Algorithm from Howard Hinnant's
    // "civil_from_days".
    let days = unix_secs.div_euclid(86400);
    let secs_of_day = unix_secs.rem_euclid(86400);
    let h = (secs_of_day / 3600) as u32;
    let m = ((secs_of_day % 3600) / 60) as u32;
    let s = (secs_of_day % 60) as u32;

    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let yr = if mo <= 2 { y + 1 } else { y };

    // Match Python's `datetime.isoformat()`: drop the `.000000` suffix
    // entirely when microseconds are zero.
    if micros == 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            yr, mo, d, h, m, s
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+00:00",
            yr, mo, d, h, m, s, micros
        )
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Result<u32> {
    if offset + 4 > buf.len() {
        return Err(Error::Eof(offset, 4));
    }
    Ok(u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()))
}

fn decode_utf16_le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Recursive walk stats, useful for benchmarking and correctness checks.
#[derive(Debug, Default, Clone, Copy)]
pub struct WalkStats {
    pub keys: u64,
    pub values: u64,
    pub max_depth: u32,
}

pub fn walk(hive: &Hive) -> Result<WalkStats> {
    let mut stats = WalkStats::default();
    let root = hive.root()?;
    walk_inner(&root, 1, &mut stats);
    Ok(stats)
}

fn walk_inner(nk: &NkRecord<'_>, depth: u32, stats: &mut WalkStats) {
    stats.keys += 1;
    stats.values += nk.values_count as u64;
    if depth > stats.max_depth {
        stats.max_depth = depth;
    }
    if nk.subkey_count == 0 {
        return;
    }
    for sk in nk.iter_subkeys() {
        walk_inner(&sk, depth + 1, stats);
    }
}

/// Walk that also reads value data — closer to Python's recurse_subkeys with values.
pub fn walk_with_values(hive: &Hive) -> Result<WalkStats> {
    let mut stats = WalkStats::default();
    let root = hive.root()?;
    walk_with_values_inner(&root, 1, &mut stats);
    Ok(stats)
}

fn walk_with_values_inner(nk: &NkRecord<'_>, depth: u32, stats: &mut WalkStats) {
    stats.keys += 1;
    if depth > stats.max_depth {
        stats.max_depth = depth;
    }
    if nk.values_count > 0 {
        for v in nk.iter_values() {
            // Touch name and bytes to defeat any laziness
            let _ = v.name();
            let bytes = v.raw_value();
            // Sum the length to ensure bytes are actually read from mmap
            stats.values = stats.values.wrapping_add(bytes.len() as u64);
        }
    }
    if nk.subkey_count == 0 {
        return;
    }
    for sk in nk.iter_subkeys() {
        walk_with_values_inner(&sk, depth + 1, stats);
    }
}
