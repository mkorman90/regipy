use crate::errors::{RegistryError, RegistryResult};
use crate::structs::*;

use std::fmt;

/// Type of a registry cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    /// Name Key — a registry key
    Nk,
    /// Leaf Index — points to NK records via LI subkeys
    Li,
    /// Fast Leaf — points to NK records via LF subkeys
    Lf,
    /// Hash Leaf — points to NK records via LH subkeys
    Lh,
    /// Root Index — points to subkey list headers
    Ri,
    /// Value Key — a registry value
    Vk,
    /// Unknown cell type
    Unknown([u8; 2]),
}

impl fmt::Display for CellType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellType::Nk => write!(f, "nk"),
            CellType::Li => write!(f, "li"),
            CellType::Lf => write!(f, "lf"),
            CellType::Lh => write!(f, "lh"),
            CellType::Ri => write!(f, "ri"),
            CellType::Vk => write!(f, "vk"),
            CellType::Unknown(bytes) => write!(f, "{:02x}{:02x}", bytes[0], bytes[1]),
        }
    }
}

/// A parsed cell header.
#[derive(Debug, Clone, Copy)]
pub struct CellHeader {
    pub size: i32,  // negative = allocated, positive = free
    pub cell_type: CellType,
}

impl CellHeader {
    /// Parse a cell header from raw bytes.
    /// The cell header is 4 bytes: 2-byte size (little-endian, signed) + 2-byte type.
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < 4 {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "Cell header too short".to_string(),
            });
        }
        let size = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let cell_type = CellType::from_bytes(&data[4..6]);
        Ok(CellHeader { size, cell_type })
    }

    /// Whether this cell is allocated (negative size).
    pub fn is_allocated(&self) -> bool {
        self.size < 0
    }

    /// The data size of an allocated cell (excludes the 4-byte header).
    pub fn data_size(&self) -> usize {
        if self.is_allocated() {
            // size is negative, data = |size| - 4 (for the header itself)
            (self.size.unsigned_abs() - 4) as usize
        } else {
            0
        }
    }
}

impl CellType {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 2 {
            return CellType::Unknown([0, 0]);
        }
        match &bytes[0..2] {
            b"nk" => CellType::Nk,
            b"li" => CellType::Li,
            b"lf" => CellType::Lf,
            b"lh" => CellType::Lh,
            b"ri" => CellType::Ri,
            b"vk" => CellType::Vk,
            other => CellType::Unknown([other[0], other[1]]),
        }
    }
}

/// A parsed NK record (Name Key) — a registry key node.
#[derive(Debug, Clone)]
pub struct NkRecord {
    pub header: CmKeyNode,
    pub name: String,
    pub subkey_count: u32,
    pub values_count: u32,
    pub volatile_subkey_count: u32,
    pub last_modified: i64,
    pub subkeys_list_offset: u32,
    pub values_list_offset: u32,
    pub security_key_offset: u32,
    pub class_name_offset: u32,
    pub class_name_size: u16,
}

impl NkRecord {
    /// Parse an NK record from raw bytes (starting after the cell header).
    pub fn from_bytes(data: &[u8]) -> RegistryResult<Self> {
        if data.len() < CM_KEY_NODE_SIZE as usize {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "NK record data too short".to_string(),
            });
        }
        let header = CmKeyNode::from_bytes(data)?;
        let name_size = header.key_name_size as usize;
        let name_start = CM_KEY_NODE_SIZE as usize;
        let name_bytes = &data[name_start..name_start + name_size];

        let name = if header.is_compressed_name() {
            String::from_utf8_lossy(name_bytes).to_string()
        } else {
            // UTF-16-LE
            let u16s: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&u16s)
                .unwrap_or_else(|_| String::from_utf8_lossy(name_bytes).to_string())
        };

        Ok(NkRecord {
            header,
            name,
            subkey_count: header.subkey_count,
            values_count: header.values_count,
            volatile_subkey_count: header.volatile_subkey_count,
            last_modified: header.last_modified,
            subkeys_list_offset: header.subkeys_list_offset,
            values_list_offset: header.values_list_offset,
            security_key_offset: header.security_key_offset,
            class_name_offset: header.class_name_offset,
            class_name_size: header.class_name_size,
        })
    }

    /// Parse values from this NK record.
    pub fn parse_values(
        &self,
        hive_data: &[u8],
        hive_offset: usize,
        as_json: bool,
    ) -> RegistryResult<crate::value::ValueList> {
        if self.values_count == 0 {
            return Ok(crate::value::ValueList::new());
        }

        let mut values_offset = hive_offset + self.values_list_offset as usize;
        let mut values = crate::value::ValueList::new();

        for _ in 0..self.values_count {
            // Each value is a 4-byte pointer to the VK record
            if values_offset + 4 > hive_data.len() {
                break;
            }
            let vk_offset = u32::from_le_bytes([
                hive_data[values_offset],
                hive_data[values_offset + 1],
                hive_data[values_offset + 2],
                hive_data[values_offset + 3],
            ]) as usize;

            let vk_abs_offset = hive_offset + vk_offset;
            if vk_abs_offset + 18 > hive_data.len() {
                break;
            }

            // Parse VK record
            let vk_data = &hive_data[vk_abs_offset..vk_abs_offset + 18];
            let name_size = u16::from_le_bytes([vk_data[2], vk_data[3]]) as usize;
            let data_size = u32::from_le_bytes([
                vk_data[4],
                vk_data[5],
                vk_data[6],
                vk_data[7],
            ]) as usize;
            let data_offset = u32::from_le_bytes([
                vk_data[8],
                vk_data[9],
                vk_data[10],
                vk_data[11],
            ]) as usize;
            let data_type = u32::from_le_bytes([
                vk_data[12],
                vk_data[13],
                vk_data[14],
                vk_data[15],
            ]);
            let flags = u16::from_le_bytes([vk_data[16], vk_data[17]]);

            // Read value name
            let name_start = vk_abs_offset + 18;
            let name_bytes = &hive_data[name_start..name_start + name_size];
            let value_name = if flags & 0x0001 != 0 {
                // Compressed (ASCII)
                String::from_utf8_lossy(name_bytes).to_string()
            } else {
                // UTF-16-LE
                let u16s: Vec<u16> = name_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&u16s)
                    .unwrap_or_else(|_| String::from_utf8_lossy(name_bytes).to_string())
            };

            // Parse the value data
            let value_data = Self::parse_value_data(
                &hive_data,
                hive_offset,
                data_type,
                data_size,
                data_offset,
                as_json,
            )?;

            values.push(crate::value::Value {
                name: value_name,
                value: value_data,
                value_type: data_type,
                is_corrupted: false,
            });

            values_offset += 4;
        }

        Ok(values)
    }

    /// Parse a single value's data based on its type and size.
    fn parse_value_data(
        hive_data: &[u8],
        hive_offset: usize,
        data_type: u32,
        data_size: usize,
        data_offset: usize,
        _as_json: bool,
    ) -> RegistryResult<crate::value::ValueData> {
        // Handle inline data (data_size >= 0x80000000 means data is inline)
        let is_inline = data_size >= 0x80000000;
        let effective_size = if is_inline {
            data_size & 0x7FFFFFFF
        } else {
            data_size
        };

        match data_type {
            0 => Ok(crate::value::ValueData::None),
            1 | 2 => {
                // REG_SZ, REG_EXPAND_SZ
                if is_inline {
                    let data = &hive_data[data_offset..data_offset + effective_size];
                    let s = String::from_utf16(
                        &data
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default();
                    Ok(crate::value::ValueData::String(
                        s.trim_end_matches('\0').to_string(),
                    ))
                } else if effective_size == 0 {
                    Ok(crate::value::ValueData::String(String::new()))
                } else {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + effective_size];
                    let s = String::from_utf16(
                        &data
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_else(|_| String::from_utf8_lossy(data).to_string());
                    Ok(crate::value::ValueData::String(
                        s.trim_end_matches('\0')
                            .chars()
                            .take(crate::structs::MAX_VALUE_LEN)
                            .collect(),
                    ))
                }
            }
            3 | 4 => {
                // REG_BINARY, REG_DWORD
                if is_inline {
                    let data = &hive_data[data_offset..data_offset + effective_size];
                    Ok(crate::value::ValueData::Bytes(data.to_vec()))
                } else if data_type == 4 && effective_size == 4 {
                    // REG_DWORD inline in data_offset
                    Ok(crate::value::ValueData::Dword(data_offset as u32))
                } else if effective_size == 4 {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + 4];
                    Ok(crate::value::ValueData::Dword(u32::from_le_bytes([
                        data[0], data[1], data[2], data[3],
                    ])))
                } else {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + effective_size];
                    Ok(crate::value::ValueData::Bytes(data.to_vec()))
                }
            }
            7 => {
                // REG_MULTI_SZ
                if is_inline {
                    let data = &hive_data[data_offset..data_offset + effective_size];
                    let s = String::from_utf16(
                        &data
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default();
                    let parts: Vec<String> = s
                        .split('\0')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    Ok(crate::value::ValueData::MultiString(parts))
                } else {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + effective_size];
                    let s = String::from_utf16(
                        &data
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap_or_default();
                    let parts: Vec<String> = s
                        .split('\0')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();
                    Ok(crate::value::ValueData::MultiString(parts))
                }
            }
            11 => {
                // REG_QWORD
                if is_inline {
                    Ok(crate::value::ValueData::Qword(data_offset as u64))
                } else if effective_size == 8 {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + 8];
                    Ok(crate::value::ValueData::Qword(u64::from_le_bytes([
                        data[0],
                        data[1],
                        data[2],
                        data[3],
                        data[4],
                        data[5],
                        data[6],
                        data[7],
                    ])))
                } else {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + effective_size];
                    Ok(crate::value::ValueData::Bytes(data.to_vec()))
                }
            }
            16 => {
                // REG_FILETIME
                let ft = if is_inline {
                    u64::from_le_bytes([
                        hive_data[data_offset],
                        hive_data[data_offset + 1],
                        hive_data[data_offset + 2],
                        hive_data[data_offset + 3],
                        hive_data[data_offset + 4],
                        hive_data[data_offset + 5],
                        hive_data[data_offset + 6],
                        hive_data[data_offset + 7],
                    ]) as i64
                } else if effective_size == 8 {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + 8];
                    u64::from_le_bytes([
                        data[0], data[1], data[2], data[3],
                        data[4], data[5], data[6], data[7],
                    ]) as i64
                } else {
                    0
                };
                let dt = crate::structs::convert_wintime(ft);
                Ok(crate::value::ValueData::FileTime(dt.to_rfc3339()))
            }
            _ => {
                // Unknown type — return raw bytes
                if is_inline {
                    let data = &hive_data[data_offset..data_offset + effective_size];
                    Ok(crate::value::ValueData::Bytes(data.to_vec()))
                } else if effective_size > 0 {
                    let data = &hive_data[hive_offset + data_offset..hive_offset + data_offset + effective_size];
                    Ok(crate::value::ValueData::Bytes(data.to_vec()))
                } else {
                    Ok(crate::value::ValueData::None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cell_type_from_bytes() {
        assert_eq!(CellType::from_bytes(b"nk"), CellType::Nk);
        assert_eq!(CellType::from_bytes(b"lf"), CellType::Lf);
        assert_eq!(CellType::from_bytes(b"lh"), CellType::Lh);
        assert_eq!(CellType::from_bytes(b"li"), CellType::Li);
        assert_eq!(CellType::from_bytes(b"ri"), CellType::Ri);
        assert_eq!(CellType::from_bytes(b"vk"), CellType::Vk);
        assert_eq!(CellType::from_bytes(b"xx"), CellType::Unknown([b'x', b'x']));
    }

    #[test]
    fn test_cell_header_allocated() {
        // -100 bytes allocated: size = -100 = 0xFFFFFF9C in little-endian
        let data = [0x9C, 0xFF, 0xFF, 0xFF, b'n', b'k'];
        let header = CellHeader::from_bytes(&data).unwrap();
        assert!(header.is_allocated());
        assert_eq!(header.size, -100);
        assert_eq!(header.data_size(), 96);
    }

    #[test]
    fn test_cell_header_free() {
        // 100 bytes free: size = 100 = 0x64 in little-endian
        let data = [0x64, 0x00, 0x00, 0x00, b'x', b'y'];
        let header = CellHeader::from_bytes(&data).unwrap();
        assert!(!header.is_allocated());
        assert_eq!(header.size, 100);
        assert_eq!(header.data_size(), 0);
    }

    #[test]
    fn test_nk_record_parse() {
        // Minimal valid NK record: 76 bytes of CM_KEY_NODE with zeroed fields
        let data = vec![0u8; 76];
        let record = NkRecord::from_bytes(&data).unwrap();
        assert_eq!(record.name, "");
        assert_eq!(record.subkey_count, 0);
        assert_eq!(record.values_count, 0);
    }
}
