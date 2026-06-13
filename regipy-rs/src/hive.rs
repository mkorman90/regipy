use crate::cell::NkRecord;
use crate::errors::{RegistryError, RegistryResult};
use crate::key::{navigate_path, SubkeyIterator};
use crate::structs::*;
use crate::value::{Value, ValueList};

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// A parsed Windows registry hive.
///
/// This is the main entry point for parsing registry hive files.
/// It provides navigation to keys, values, and recursive traversal.
pub struct RegistryHive {
    /// Parsed REGF header
    pub header: RegfHeader,
    /// Raw hive data
    data: Vec<u8>,
    /// The root NK record
    pub root: NkRecord,
    /// Identified hive type (e.g., NTUSER, SYSTEM)
    pub hive_type: Option<HiveType>,
    /// For partial hives, the path from which this hive actually starts
    pub partial_hive_path: Option<String>,
}

impl RegistryHive {
    /// Load a hive from a file path.
    pub fn from_path(path: &Path) -> RegistryResult<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Self::from_bytes(data)
    }

    /// Load a hive from raw bytes.
    pub fn from_bytes(data: Vec<u8>) -> RegistryResult<Self> {
        if data.len() < REGF_HEADER_SIZE as usize {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: "File too small to be a registry hive".to_string(),
            });
        }

        // Parse REGF header
        let header = RegfHeader::from_bytes(&data[0..REGF_HEADER_SIZE as usize])?;

        // Validate signature
        if header.signature != *b"regf" {
            return Err(RegistryError::Parsing {
                offset: 0,
                reason: format!("Invalid REGF signature: {:?}", header.signature),
            });
        }

        // Check dirty state
        if header.is_dirty() {
            eprintln!(
                "Warning: Hive is dirty (primary={} != secondary={})",
                header.primary_sequence_num, header.secondary_sequence_num
            );
        }

        // Parse the root NK record
        // The root key is at root_key_offset in the first hbin
        let root_offset = header.root_key_offset as usize;
        let root_data_start = REGF_HEADER_SIZE as usize + root_offset;

        // Cell header is 6 bytes: 4 bytes size + 2 bytes type
        if root_data_start + 6 > data.len() {
            return Err(RegistryError::Parsing {
                offset: root_data_start,
                reason: "Root key offset out of bounds".to_string(),
            });
        }

        // Cell type is at offset +4 (after the 4-byte size field)
        let root_cell_type = &data[root_data_start + 4..root_data_start + 6];
        if &root_cell_type[0..2] != b"nk" {
            return Err(RegistryError::Parsing {
                offset: root_data_start,
                reason: format!("Expected NK cell at root, got {:?}", root_cell_type),
            });
        }

        let root_nk = NkRecord::from_bytes(&data[root_data_start..])?;

        // Identify hive type from file name
        let hive_type = header.file_name().ok().and_then(|name| {
            HiveType::from_hive_name(&name).ok()
        });

        Ok(RegistryHive {
            header,
            data,
            root: root_nk,
            hive_type,
            partial_hive_path: None,
        })
    }

    /// Get the hive type.
    pub fn hive_type(&self) -> Option<&HiveType> {
        self.hive_type.as_ref()
    }

    /// Check if the hive is dirty (sequence numbers don't match).
    pub fn is_dirty(&self) -> bool {
        self.header.is_dirty()
    }

    /// Get the raw data slice.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    // ─── Key Navigation ─────────────────────────────────────────────────────

    /// Get a key by path (e.g., "Software\\Microsoft\\Windows").
    /// The path is relative to the root of the hive.
    pub fn get_key(&self, key_path: &str) -> RegistryResult<NkRecord> {
        // Handle partial hive paths
        let effective_path = if let Some(ref partial) = self.partial_hive_path {
            if key_path.starts_with(partial.as_str()) {
                key_path[partial.len()..].to_string()
            } else {
                return Err(RegistryError::KeyNotFound(format!(
                    "Path {} does not start with partial hive path {}",
                    key_path, partial
                )));
            }
        } else {
            key_path.to_string()
        };

        // Handle root path
        if effective_path == "\\" || effective_path.is_empty() {
            return Ok(self.root.clone());
        }

        // Split path by backslash
        let segments: Vec<&str> = effective_path
            .split('\\')
            .filter(|s| !s.is_empty())
            .collect();

        if segments.is_empty() {
            return Ok(self.root.clone());
        }

        match navigate_path(&self.root, &self.data, REGF_HEADER_SIZE as usize, &segments) {
            Some(nk) => Ok(nk),
            None => Err(RegistryError::KeyNotFound(format!(
                "Key not found: {}",
                key_path
            ))),
        }
    }

    /// Get a key by path, returning None if not found.
    pub fn get_key_opt(&self, key_path: &str) -> Option<NkRecord> {
        self.get_key(key_path).ok()
    }

    /// Get all control sets (ControlSet001, ControlSet002, etc.).
    pub fn get_control_sets(&self, registry_path: &str) -> RegistryResult<Vec<NkRecord>> {
        let mut results = Vec::new();
        for cs in ["ControlSet001", "ControlSet002"] {
            let full_path = format!("\\{}\\{}", cs, registry_path);
            if let Ok(nk) = self.get_key(&full_path) {
                results.push(nk);
            }
        }
        Ok(results)
    }

    // ─── Iteration ────────────────────────────────────────────────────────────

    /// Recursively iterate over all subkeys starting from the root.
    ///
    /// Yields `SubkeyEntry` for each key visited, in depth-first order.
    pub fn recurse_subkeys(&self) -> SubkeyIterator<'_> {
        SubkeyIterator::new(&self.root, &self.data, REGF_HEADER_SIZE as usize)
    }

    /// Recursively iterate over all subkeys starting from a specific key.
    pub fn recurse_subkeys_from<'a>(&'a self, start: &'a NkRecord) -> SubkeyIterator<'a> {
        SubkeyIterator::new(start, &self.data, REGF_HEADER_SIZE as usize)
    }

    // ─── Value Access ─────────────────────────────────────────────────────────

    /// Get a value by name from a key.
    pub fn get_value(&self, key_path: &str, value_name: &str) -> RegistryResult<Value> {
        let nk = self.get_key(key_path)?;
        let values = nk.parse_values(&self.data, REGF_HEADER_SIZE as usize, false)?;
        for v in &values.0 {
            if v.name == value_name {
                return Ok(v.clone());
            }
        }
        Err(RegistryError::ValueNotFound(format!(
            "Value '{}' not found in key '{}'",
            value_name, key_path
        )))
    }

    /// Get all values from a key.
    pub fn get_values(&self, key_path: &str) -> RegistryResult<ValueList> {
        let nk = self.get_key(key_path)?;
        nk.parse_values(&self.data, REGF_HEADER_SIZE as usize, false)
    }
}

/// Cell iterator — iterates over all allocated cells in the hive data.
pub struct CellIterator<'a> {
    data: &'a [u8],
    offset: usize,
    end: usize,
}

impl<'a> CellIterator<'a> {
    pub fn new(data: &'a [u8], start: usize, end: usize) -> Self {
        CellIterator {
            data,
            offset: start,
            end,
        }
    }
}

impl<'a> Iterator for CellIterator<'a> {
    type Item = RegistryResult<(crate::cell::CellType, usize)>; // (cell_type, offset)

    fn next(&mut self) -> Option<Self::Item> {
        while self.offset + 6 <= self.end {
            let cell_size = i32::from_le_bytes([
                self.data[self.offset],
                self.data[self.offset + 1],
                self.data[self.offset + 2],
                self.data[self.offset + 3],
            ]);

            self.offset += 4;

            // Skip free cells (positive size)
            if cell_size >= 0 {
                self.offset += cell_size as usize;
                continue;
            }

            if self.offset + 2 > self.end {
                return Some(Err(RegistryError::Parsing {
                    offset: self.offset,
                    reason: "Cell type truncated".to_string(),
                }));
            }

            let cell_type = crate::cell::CellType::from_bytes(&self.data[self.offset..self.offset + 2]);
            let cell_offset = self.offset;
            self.offset += 2 + (cell_size.unsigned_abs() - 4) as usize;

            return Some(Ok((cell_type, cell_offset)));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bytes_too_small() {
        let result = RegistryHive::from_bytes(vec![0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_invalid_signature() {
        let data = vec![0u8; 4096];
        let result = RegistryHive::from_bytes(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_hive_type_identification() {
        // Create a minimal valid hive with a known name
        // REGF header (4096) + HBIN data with root NK record (4096) = 8192 bytes
        let mut data = vec![0u8; 8192];
        // Write "regf" signature
        data[0..4].copy_from_slice(b"regf");
        // Write file name "SYSTEM" in UTF-16-LE at offset 48
        for (i, c) in "SYSTEM".encode_utf16().enumerate() {
            data[48 + i * 2] = (c & 0xFF) as u8;
            data[48 + i * 2 + 1] = (c >> 8) as u8;
        }
        // Write root_key_offset = 0 (first cell in HBIN, which starts at offset 4096)
        data[28..32].copy_from_slice(&0u32.to_le_bytes());
        // Write the root NK cell header at offset 4096: -76 bytes (allocated) + "nk"
        data[4096..4100].copy_from_slice(&(-76i32).to_le_bytes());
        data[4100..4102].copy_from_slice(b"nk");

        let result = RegistryHive::from_bytes(data);
        // Should succeed with SYSTEM hive type
        assert!(result.is_ok(), "Failed to parse hive: {:?}", result.err());
        if let Ok(hive) = result {
            assert_eq!(hive.hive_type, Some(HiveType::System));
        }
    }
}
