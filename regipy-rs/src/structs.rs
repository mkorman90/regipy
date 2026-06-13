use bitflags::bitflags;
use chrono::{DateTime, Utc};

use crate::errors::{RegistryError, RegistryResult};

// ─── Constants ───────────────────────────────────────────────────────────────

pub const REGF_HEADER_SIZE: u32 = 4096;
pub const HBIN_HEADER_SIZE: u32 = 28;
pub const CM_KEY_NODE_SIZE: u32 = 76;
pub const MAX_VALUE_LEN: usize = 256;

// ─── Hive Type Identification ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HiveType {
    Ntuser,
    System,
    Software,
    Sam,
    Security,
    Bcd,
    Usrclass,
    Amcache,
    ClassesRoot,
    Unknown(String),
}

impl HiveType {
    pub fn from_hive_name(name: &str) -> RegistryResult<Self> {
        let name = name.to_lowercase();
        match name.as_str() {
            n if n.ends_with("ntuser.dat") => Ok(HiveType::Ntuser),
            "system" => Ok(HiveType::System),
            n if n.ends_with("system32\\config\\software") => Ok(HiveType::Software),
            n if n.contains("config\\sam") => Ok(HiveType::Sam),
            n if n.contains("config\\security") => Ok(HiveType::Security),
            n if n.ends_with("\\bcd") || n.ends_with("boot\\bcd") => Ok(HiveType::Bcd),
            n if n.ends_with("usrclass.dat") => Ok(HiveType::Usrclass),
            n if n.contains("amcache") => Ok(HiveType::Amcache),
            n if n.contains("classes") => Ok(HiveType::ClassesRoot),
            _ => Err(RegistryError::UnidentifiedHive(name)),
        }
    }
}

// ─── REGF Header (4096 bytes) ───────────────────────────────────────────────

/// Registry file header — first 4096 bytes of every hive file.
///
/// We use `#[repr(C)]` and manual byte access rather than `bytemuck::Pod`
/// because `[u8; 396]` doesn't implement `Pod`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RegfHeader {
    pub signature: [u8; 4],       // "regf"
    pub primary_sequence_num: u32,
    pub secondary_sequence_num: u32,
    pub last_modification_time: i64,
    pub major_version: u32,
    pub minor_version: u32,
    pub file_type: u32,           // 1 = main hive, 2 = .log, 3 = .rem
    pub file_format: u32,         // always 1
    pub root_key_offset: u32,
    pub hive_bins_data_size: u32,
    pub clustering_factor: u32,
    pub file_name: [u8; 64],      // UTF-16-LE padded
    pub padding: [u8; 396],
    pub checksum: u32,
}

impl RegfHeader {
    /// Parse a REGF header from raw bytes.
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 4096 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "REGF header too small".to_string(),
            });
        }
        let mut file_name = [0u8; 64];
        file_name.copy_from_slice(&data[48..112]);
        let mut padding = [0u8; 396];
        padding.copy_from_slice(&data[112..508]);
        Ok(RegfHeader {
            signature: [data[0], data[1], data[2], data[3]],
            primary_sequence_num: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            secondary_sequence_num: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            last_modification_time: i64::from_le_bytes([
                data[12], data[13], data[14], data[15],
                data[16], data[17], data[18], data[19],
            ]),
            major_version: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            minor_version: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            file_type: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            file_format: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            root_key_offset: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            hive_bins_data_size: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            clustering_factor: u32::from_le_bytes([data[44], data[45], data[46], data[47]]),
            file_name,
            padding,
            checksum: u32::from_le_bytes([data[508], data[509], data[510], data[511]]),
        })
    }

    pub fn file_name(&self) -> RegistryResult<String> {
        // UTF-16-LE, null-terminated
        let name_bytes = &self.file_name;
        let end = name_bytes
            .chunks_exact(2)
            .position(|chunk| chunk == [0, 0])
            .unwrap_or(name_bytes.len() / 2);
        let name_slice = &name_bytes[..end * 2];
        let u16s: Vec<u16> = name_slice
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&u16s)
            .map_err(|e| RegistryError::Parsing {
                offset: 0,
                reason: format!("Invalid UTF-16 in file name: {}", e),
            })
    }

    pub fn is_dirty(&self) -> bool {
        self.primary_sequence_num != self.secondary_sequence_num
    }
}

// ─── HBIN Header (28 bytes) ─────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HbinHeader {
    pub signature: [u8; 4], // "hbin"
    pub offset: u32,        // offset from start of hive file to this hbin data
    pub size: u32,          // size of this hbin block in bytes
    _unknown1: u32,
    _unknown2: u32,
    pub timestamp: i64,
    _unknown3: u32,
}

impl HbinHeader {
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 28 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "HBIN header too small".to_string(),
            });
        }
        Ok(HbinHeader {
            signature: [data[0], data[1], data[2], data[3]],
            offset: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            _unknown1: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            _unknown2: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            timestamp: i64::from_le_bytes([
                data[20], data[21], data[22], data[23],
                data[24], data[25], data[26], data[27],
            ]),
            _unknown3: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
        })
    }
}

// ─── CM_KEY_NODE (76 bytes) ─────────────────────────────────────────────────

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyNodeFlags: u16 {
        const KEY_VOLATILE = 0x0001;
        const KEY_HIVE_EXIT = 0x0002;
        const KEY_HIVE_ENTRY = 0x0004;
        const KEY_NO_DELETE = 0x0008;
        const KEY_SYM_LINK = 0x0010;
        const KEY_COMP_NAME = 0x0020; // compressed (ASCII) name
        const KEY_PREDEF_HANDLE = 0x0040;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CmKeyNode {
    pub flags: u16,
    pub last_modified: i64,
    pub access_bits: u32,
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
    _unknown: u32,
    pub key_name_size: u16,
    pub class_name_size: u16,
    // key_name_string follows immediately (variable length)
}

impl CmKeyNode {
    /// Parse from raw bytes (76 bytes).
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 76 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "CM_KEY_NODE data too short".to_string(),
            });
        }
        Ok(CmKeyNode {
            flags: u16::from_le_bytes([data[0], data[1]]),
            last_modified: i64::from_le_bytes([
                data[2], data[3], data[4], data[5],
                data[6], data[7], data[8], data[9],
            ]),
            access_bits: u32::from_le_bytes([data[10], data[11], data[12], data[13]]),
            parent_key_offset: u32::from_le_bytes([data[14], data[15], data[16], data[17]]),
            subkey_count: u32::from_le_bytes([data[18], data[19], data[20], data[21]]),
            volatile_subkey_count: u32::from_le_bytes([data[22], data[23], data[24], data[25]]),
            subkeys_list_offset: u32::from_le_bytes([data[26], data[27], data[28], data[29]]),
            volatile_subkeys_list_offset: u32::from_le_bytes([data[30], data[31], data[32], data[33]]),
            values_count: u32::from_le_bytes([data[34], data[35], data[36], data[37]]),
            values_list_offset: u32::from_le_bytes([data[38], data[39], data[40], data[41]]),
            security_key_offset: u32::from_le_bytes([data[42], data[43], data[44], data[45]]),
            class_name_offset: u32::from_le_bytes([data[46], data[47], data[48], data[49]]),
            largest_sk_name: u32::from_le_bytes([data[50], data[51], data[52], data[53]]),
            largest_sk_class_name: u32::from_le_bytes([data[54], data[55], data[56], data[57]]),
            largest_value_name: u32::from_le_bytes([data[58], data[59], data[60], data[61]]),
            largest_value_data: u32::from_le_bytes([data[62], data[63], data[64], data[65]]),
            _unknown: u32::from_le_bytes([data[66], data[67], data[68], data[69]]),
            key_name_size: u16::from_le_bytes([data[70], data[71]]),
            class_name_size: u16::from_le_bytes([data[72], data[73]]),
        })
    }

    pub fn is_compressed_name(&self) -> bool {
        self.flags & KeyNodeFlags::KEY_COMP_NAME.bits() != 0
    }
}

// ─── Value Type Enum ─────────────────────────────────────────────────────────

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    None = 0,
    Sz = 1,
    ExpandSz = 2,
    Binary = 3,
    Dword = 4,
    DwordBigEndian = 5,
    Link = 6,
    MultiSz = 7,
    ResourceList = 8,
    FullResourceDescriptor = 9,
    ResourceRequirementsList = 10,
    Qword = 11,
    FileTime = 16,
}

impl TryFrom<u32> for ValueType {
    type Error = RegistryError;
    fn try_from(v: u32) -> RegistryResult<Self> {
        match v {
            0 => Ok(ValueType::None),
            1 => Ok(ValueType::Sz),
            2 => Ok(ValueType::ExpandSz),
            3 => Ok(ValueType::Binary),
            4 => Ok(ValueType::Dword),
            5 => Ok(ValueType::DwordBigEndian),
            6 => Ok(ValueType::Link),
            7 => Ok(ValueType::MultiSz),
            8 => Ok(ValueType::ResourceList),
            9 => Ok(ValueType::FullResourceDescriptor),
            10 => Ok(ValueType::ResourceRequirementsList),
            11 => Ok(ValueType::Qword),
            16 => Ok(ValueType::FileTime),
            _ => Err(RegistryError::Parsing {
                offset: 0,
                reason: format!("Unknown value type: {}", v),
            }),
        }
    }
}

// ─── VALUE_KEY (VK Record) ───────────────────────────────────────────────────

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VkFlags: u16 {
        const VALUE_COMP_NAME = 0x0001; // compressed (ASCII) name
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VkRecord {
    pub signature: [u8; 2], // "vk"
    pub name_size: u16,
    pub data_size: u32,
    pub data_offset: u32,
    pub data_type: u32,
    pub flags: u16,
    pub padding: u16,
    // name follows (variable length, name_size bytes)
}

impl VkRecord {
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 18 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "VK record too short".to_string(),
            });
        }
        Ok(VkRecord {
            signature: [data[0], data[1]],
            name_size: u16::from_le_bytes([data[2], data[3]]),
            data_size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            data_offset: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            data_type: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            flags: u16::from_le_bytes([data[16], data[17]]),
            padding: u16::from_le_bytes([data[18], data[19]]),
        })
    }

    pub fn is_compressed_name(&self) -> bool {
        self.flags & VkFlags::VALUE_COMP_NAME.bits() != 0
    }
}

// ─── Subkey List Signatures ──────────────────────────────────────────────────

pub const HASH_LEAF_SIGNATURE: &[u8; 2] = b"lh";
pub const FAST_LEAF_SIGNATURE: &[u8; 2] = b"lf";
pub const LEAF_INDEX_SIGNATURE: &[u8; 2] = b"li";
pub const INDEX_ROOT_SIGNATURE: &[u8; 2] = b"ri";

// ─── Transaction Log (HvLE) ─────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransactionLogHeader {
    pub signature: [u8; 4], // "HvLE"
    pub log_size: u32,
    pub flags: u32,
    pub sequence_number: u32,
    pub hive_bin_size: u32,
    pub dirty_pages_count: u32,
    pub hash_1: u64,
    pub hash_2: u64,
    // followed by dirty_pages_count * (offset: u32, size: u32)
}

impl TransactionLogHeader {
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 40 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "Transaction log header too short".to_string(),
            });
        }
        Ok(TransactionLogHeader {
            signature: [data[0], data[1], data[2], data[3]],
            log_size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            flags: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            sequence_number: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            hive_bin_size: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            dirty_pages_count: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            hash_1: u64::from_le_bytes([
                data[24], data[25], data[26], data[27],
                data[28], data[29], data[30], data[31],
            ]),
            hash_2: u64::from_le_bytes([
                data[32], data[33], data[34], data[35],
                data[36], data[37], data[38], data[39],
            ]),
        })
    }
}

// ─── Big Data Block (db) ────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BigDataBlock {
    pub signature: [u8; 2], // "db"
    pub number_of_segments: u16,
    pub offset_to_list_of_segments: u32,
}

impl BigDataBlock {
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 8 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "Big data block too short".to_string(),
            });
        }
        Ok(BigDataBlock {
            signature: [data[0], data[1]],
            number_of_segments: u16::from_le_bytes([data[2], data[3]]),
            offset_to_list_of_segments: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

// ─── Security Descriptor ────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub owner: u32,
    pub group: u32,
    pub offset_sacl: u32,
    pub offset_dacl: u32,
}

impl SecurityDescriptor {
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 16 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "Security descriptor too short".to_string(),
            });
        }
        Ok(SecurityDescriptor {
            revision: data[0],
            sbz1: data[1],
            control: u16::from_le_bytes([data[2], data[3]]),
            owner: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            group: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            offset_sacl: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            offset_dacl: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        })
    }
}

// ─── ACL ────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AclHeader {
    pub revision: u8,
    pub sbz1: u8,
    pub acl_size: u16,
    pub ace_count: u16,
    pub sbz2: u16,
}

impl AclHeader {
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 8 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "ACL header too short".to_string(),
            });
        }
        Ok(AclHeader {
            revision: data[0],
            sbz1: data[1],
            acl_size: u16::from_le_bytes([data[2], data[3]]),
            ace_count: u16::from_le_bytes([data[4], data[5]]),
            sbz2: u16::from_le_bytes([data[6], data[7]]),
        })
    }
}

// ─── ACE ─────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AceHeader {
    pub ace_type: u8,
    pub flags: u8,
    pub size: u16,
    pub access_mask: u32,
    // sid follows (variable length)
}

impl AceHeader {
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 8 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "ACE header too short".to_string(),
            });
        }
        Ok(AceHeader {
            ace_type: data[0],
            flags: data[1],
            size: u16::from_le_bytes([data[2], data[3]]),
            access_mask: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

// ─── Utility Functions ───────────────────────────────────────────────────────

/// Convert Windows FILETIME (100-nanosecond intervals since 1601-01-01) to
/// a chrono DateTime<Utc>.
pub fn convert_wintime(filetime: i64) -> DateTime<Utc> {
    // FILETIME is 100-ns intervals since 1601-01-01.
    // Unix epoch is 1970-01-01, which is 11644473600 seconds after 1601-01-01.
    const EPOCH_OFFSET: i64 = 11644473600;
    
    if filetime <= 0 {
        return DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_default();
    }
    let microseconds = (filetime as i128) / 10;
    // Convert to Unix timestamp by subtracting the epoch offset
    let unix_secs = (microseconds / 1_000_000) as i64 - EPOCH_OFFSET;
    let nanos = ((microseconds % 1_000_000) * 1_000) as u32;
    DateTime::<Utc>::from_timestamp(unix_secs, nanos).unwrap_or_default()
}

/// Calculate XOR-32 checksum over a buffer (must be multiple of 4 bytes).
/// Uses big-endian byte order to match the Python implementation.
pub fn calculate_xor32_checksum(data: &[u8]) -> RegistryResult<u32> {
    if data.len() % 4 != 0 {
        return Err(RegistryError::Parsing {
            offset: 0,
            reason: format!("Buffer length {} is not a multiple of 4", data.len()),
        });
    }
    let mut checksum: u32 = 0;
    for chunk in data.chunks_exact(4) {
        // Big-endian byte order (matching Python: b[i] + (b[i+1] << 8) + ...)
        let word = (chunk[0] as u32)
            | ((chunk[1] as u32) << 8)
            | ((chunk[2] as u32) << 16)
            | ((chunk[3] as u32) << 24);
        checksum ^= word;
    }
    Ok(checksum)
}

/// Try to decode binary data as a string (UTF-16-LE first, then ASCII).
pub fn try_decode_binary(data: &[u8], max_len: usize) -> String {
    // Try UTF-16-LE first
    if data.len() % 2 == 0 {
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if let Ok(s) = String::from_utf16(&u16s) {
            return s.trim_end_matches('\0').chars().take(max_len).collect();
        }
    }
    // Try ASCII / UTF-8
    if let Ok(s) = std::str::from_utf8(data) {
        return s.trim_end_matches('\0').chars().take(max_len).collect();
    }
    // Fallback: hex encoding
    data.iter()
        .take(max_len)
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn test_convert_wintime() {
        // 2024-01-01 00:00:00 UTC in FILETIME
        // 2024-01-01 = 133403008000000000 100-ns intervals since 1601-01-01
        let ft: i64 = 133485408000000000i64;
        let dt = convert_wintime(ft);
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
    }

    #[test]
    fn test_convert_wintime_zero() {
        let dt = convert_wintime(0);
        assert_eq!(dt.year(), 1970);
    }

    #[test]
    fn test_xor32_checksum() {
        // Python version uses big-endian byte order: b[i] + (b[i+1] << 8) + ...
        let data = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let checksum = calculate_xor32_checksum(data).unwrap();
        // 0x01020304 ^ 0x05060708 in big-endian interpretation
        assert_eq!(checksum, 0x0C040404);
    }

    #[test]
    fn test_xor32_checksum_invalid_length() {
        let data = b"\x01\x02\x03";
        assert!(calculate_xor32_checksum(data).is_err());
    }

    #[test]
    fn test_try_decode_binary_utf16() {
        // "Hi" in UTF-16-LE
        let data = b"H\x00i\x00";
        assert_eq!(try_decode_binary(data, 256), "Hi");
    }

    #[test]
    fn test_try_decode_binary_ascii() {
        // Odd length so UTF-16-LE fails and falls through to ASCII
        let data = b"hello\x00\x01";
        assert_eq!(try_decode_binary(data, 256), "hello\0\x01");
    }

    #[test]
    fn test_try_decode_binary_hex() {
        // Odd length so UTF-16-LE fails and falls through to hex
        let data = b"\xff\xfe\x01";
        let result = try_decode_binary(data, 256);
        assert!(result.contains("ff"));
        assert!(result.contains("fe"));
    }

    #[test]
    fn test_hive_type_identification() {
        assert_eq!(
            HiveType::from_hive_name("NTUSER.DAT").unwrap(),
            HiveType::Ntuser
        );
        assert_eq!(
            HiveType::from_hive_name("system").unwrap(),
            HiveType::System
        );
        assert_eq!(
            HiveType::from_hive_name(r"C:\Windows\System32\config\software").unwrap(),
            HiveType::Software
        );
        assert!(HiveType::from_hive_name("unknown_file").is_err());
    }

    #[test]
    fn test_regf_header_parse() {
        let mut data = vec![0u8; 4096];
        data[0..4].copy_from_slice(b"regf");
        let header = RegfHeader::from_bytes(&data).unwrap();
        assert_eq!(header.signature, *b"regf");
    }

    #[test]
    fn test_cm_key_node_parse() {
        let data = vec![0u8; 76];
        let node = CmKeyNode::from_bytes(&data).unwrap();
        assert_eq!(node.subkey_count, 0);
        assert_eq!(node.values_count, 0);
    }

    #[test]
    fn test_vk_record_parse() {
        // VK record header is 18 bytes, plus variable-length name field
        let mut data = vec![0u8; 20]; // 18 header + 2 bytes name
        data[0..2].copy_from_slice(b"vk");
        let vk = VkRecord::from_bytes(&data).unwrap();
        assert_eq!(vk.signature, *b"vk");
    }
}
