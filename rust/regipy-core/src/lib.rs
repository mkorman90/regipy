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

    fn data(&self) -> &[u8] {
        self.backing.as_ref()
    }

    pub fn root(&self) -> Result<NkRecord<'_>> {
        // root_offset is offset into hbin data; +4 to skip cell-size header
        let cell_data_offset = REGF_HEADER_SIZE + self.root_offset as usize + 4;
        NkRecord::parse_at(self.data(), cell_data_offset)
    }
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
    fn parse_at(data: &'a [u8], offset: usize) -> Result<Self> {
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
