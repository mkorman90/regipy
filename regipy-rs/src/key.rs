use crate::cell::NkRecord;
use crate::errors::{RegistryError, RegistryResult};
use crate::structs::*;

use std::fmt;

/// A parsed subkey entry for iteration/traversal.
#[derive(Debug, Clone)]
pub struct SubkeyEntry {
    pub name: String,
    pub path: String,
    pub last_modified: i64,
    pub subkey_count: u32,
    pub values_count: u32,
}

impl fmt::Display for SubkeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} subkeys, {} values)", self.path, self.subkey_count, self.values_count)
    }
}

/// Iterator over subkeys of an NK record.
/// Yields owned `NkRecord` for each direct child subkey.
pub struct SubkeyIterator<'a> {
    nk: &'a NkRecord,
    hive_data: &'a [u8],
    hive_offset: usize,
    position: SubkeyPosition,
}

/// Position in the subkey list parsing state machine.
enum SubkeyPosition {
    /// Not yet started — need to determine the subkey list type
    Initial,
    /// Parsing a hash leaf (lh)
    HashLeaf {
        offset: usize,
        remaining: u16,
    },
    /// Parsing a fast leaf (lf)
    FastLeaf {
        offset: usize,
        remaining: u16,
    },
    /// Parsing a leaf index (li)
    LeafIndex {
        offset: usize,
        remaining: u16,
    },
    /// Parsing an index root (ri) — iterating over elements
    IndexRoot {
        offset: usize,
        remaining: u16,
    },
    /// Done
    Done,
}

impl<'a> SubkeyIterator<'a> {
    pub fn new(nk: &'a NkRecord, hive_data: &'a [u8], hive_offset: usize) -> Self {
        SubkeyIterator {
            nk,
            hive_data,
            hive_offset,
            position: SubkeyPosition::Initial,
        }
    }
}

impl<'a> Iterator for SubkeyIterator<'a> {
    type Item = RegistryResult<NkRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Take ownership of the current position to avoid borrow conflicts
            let result = match std::mem::replace(&mut self.position, SubkeyPosition::Done) {
                SubkeyPosition::Initial => self.handle_initial(),
                SubkeyPosition::HashLeaf { offset, remaining } => self.handle_hash_leaf(offset, remaining),
                SubkeyPosition::FastLeaf { offset, remaining } => self.handle_fast_leaf(offset, remaining),
                SubkeyPosition::LeafIndex { offset, remaining } => self.handle_leaf_index(offset, remaining),
                SubkeyPosition::IndexRoot { offset, remaining } => self.handle_index_root(offset, remaining),
                SubkeyPosition::Done => return None,
            };

            // If we got a "need to continue" signal, loop again
            if result.is_none() {
                continue;
            }
            return result;
        }
    }
}

impl<'a> SubkeyIterator<'a> {
    fn handle_initial(&mut self) -> Option<RegistryResult<NkRecord>> {
        // Read the subkey list header at subkeys_list_offset
        let header_offset = self.hive_offset + self.nk.subkeys_list_offset as usize;
        if header_offset + 4 > self.hive_data.len() {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset: header_offset,
                reason: "Subkey list header out of bounds".to_string(),
            }));
        }

        let sig = &self.hive_data[header_offset..header_offset + 2];
        let elem_count = u16::from_le_bytes([
            self.hive_data[header_offset + 2],
            self.hive_data[header_offset + 3],
        ]) as u16;

        if sig == HASH_LEAF_SIGNATURE {
            self.position = SubkeyPosition::HashLeaf {
                offset: header_offset + 4,
                remaining: elem_count,
            };
        } else if sig == FAST_LEAF_SIGNATURE {
            self.position = SubkeyPosition::FastLeaf {
                offset: header_offset + 4,
                remaining: elem_count,
            };
        } else if sig == LEAF_INDEX_SIGNATURE {
            self.position = SubkeyPosition::LeafIndex {
                offset: header_offset + 4,
                remaining: elem_count,
            };
        } else if sig == INDEX_ROOT_SIGNATURE {
            self.position = SubkeyPosition::IndexRoot {
                offset: header_offset + 4,
                remaining: elem_count,
            };
        } else {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset: header_offset,
                reason: format!("Unknown subkey list signature: {:?}", sig),
            }));
        }
        None // Signal to continue iterating
    }

    fn handle_hash_leaf(&mut self, offset: usize, remaining: u16) -> Option<RegistryResult<NkRecord>> {
        if remaining == 0 {
            self.position = SubkeyPosition::Done;
            return None;
        }

        if offset + 8 > self.hive_data.len() {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset,
                reason: "Hash leaf element truncated".to_string(),
            }));
        }

        let key_node_offset = u32::from_le_bytes([
            self.hive_data[offset],
            self.hive_data[offset + 1],
            self.hive_data[offset + 2],
            self.hive_data[offset + 3],
        ]);

        let nk_abs_offset = self.hive_offset + key_node_offset as usize;
        self.position = SubkeyPosition::HashLeaf {
            offset: offset + 8,
            remaining: remaining - 1,
        };

        Some(Self::parse_nk_at(self.hive_data, nk_abs_offset))
    }

    fn handle_fast_leaf(&mut self, offset: usize, remaining: u16) -> Option<RegistryResult<NkRecord>> {
        if remaining == 0 {
            self.position = SubkeyPosition::Done;
            return None;
        }

        if offset + 8 > self.hive_data.len() {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset,
                reason: "Fast leaf element truncated".to_string(),
            }));
        }

        let key_node_offset = u32::from_le_bytes([
            self.hive_data[offset],
            self.hive_data[offset + 1],
            self.hive_data[offset + 2],
            self.hive_data[offset + 3],
        ]);

        let nk_abs_offset = self.hive_offset + key_node_offset as usize;
        self.position = SubkeyPosition::FastLeaf {
            offset: offset + 8,
            remaining: remaining - 1,
        };

        Some(Self::parse_nk_at(self.hive_data, nk_abs_offset))
    }

    fn handle_leaf_index(&mut self, offset: usize, remaining: u16) -> Option<RegistryResult<NkRecord>> {
        if remaining == 0 {
            self.position = SubkeyPosition::Done;
            return None;
        }

        if offset + 4 > self.hive_data.len() {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset,
                reason: "Leaf index element truncated".to_string(),
            }));
        }

        let key_node_offset = u32::from_le_bytes([
            self.hive_data[offset],
            self.hive_data[offset + 1],
            self.hive_data[offset + 2],
            self.hive_data[offset + 3],
        ]);

        let nk_abs_offset = self.hive_offset + key_node_offset as usize;
        self.position = SubkeyPosition::LeafIndex {
            offset: offset + 4,
            remaining: remaining - 1,
        };

        Some(Self::parse_nk_at(self.hive_data, nk_abs_offset))
    }

    fn handle_index_root(&mut self, offset: usize, remaining: u16) -> Option<RegistryResult<NkRecord>> {
        if remaining == 0 {
            self.position = SubkeyPosition::Done;
            return None;
        }

        if offset + 4 > self.hive_data.len() {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset,
                reason: "Index root element truncated".to_string(),
            }));
        }

        let subkey_list_offset = u32::from_le_bytes([
            self.hive_data[offset],
            self.hive_data[offset + 1],
            self.hive_data[offset + 2],
            self.hive_data[offset + 3],
        ]);

        // Now we need to parse the subkey list at this offset
        // This could be lh, lf, or li
        let list_offset = self.hive_offset + subkey_list_offset as usize;
        if list_offset + 4 > self.hive_data.len() {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset: list_offset,
                reason: "Subkey list pointer out of bounds".to_string(),
            }));
        }

        let sig = &self.hive_data[list_offset..list_offset + 2];
        let elem_count = u16::from_le_bytes([
            self.hive_data[list_offset + 2],
            self.hive_data[list_offset + 3],
        ]) as u16;

        if sig == HASH_LEAF_SIGNATURE {
            self.position = SubkeyPosition::HashLeaf {
                offset: list_offset + 4,
                remaining: elem_count,
            };
        } else if sig == FAST_LEAF_SIGNATURE {
            self.position = SubkeyPosition::FastLeaf {
                offset: list_offset + 4,
                remaining: elem_count,
            };
        } else if sig == LEAF_INDEX_SIGNATURE {
            self.position = SubkeyPosition::LeafIndex {
                offset: list_offset + 4,
                remaining: elem_count,
            };
        } else {
            self.position = SubkeyPosition::Done;
            return Some(Err(RegistryError::Parsing {
                offset: list_offset,
                reason: format!("Unknown subkey list signature in index root: {:?}", sig),
            }));
        }

        // Don't advance — we need to process this new position
        // Return None to signal we need to continue iterating
        None
    }

    fn parse_nk_at(hive_data: &[u8], abs_offset: usize) -> RegistryResult<NkRecord> {
        // Read cell header
        if abs_offset + 4 > hive_data.len() {
            return Err(RegistryError::Parsing {
                offset: abs_offset,
                reason: "Cell header out of bounds".to_string(),
            });
        }

        let cell_size = i32::from_le_bytes([
            hive_data[abs_offset],
            hive_data[abs_offset + 1],
            hive_data[abs_offset + 2],
            hive_data[abs_offset + 3],
        ]);

        if cell_size >= 0 {
            return Err(RegistryError::Parsing {
                offset: abs_offset,
                reason: "Expected allocated cell (negative size)".to_string(),
            });
        }

        let cell_type_bytes = &hive_data[abs_offset + 4..abs_offset + 6];
        if &cell_type_bytes[0..2] != b"nk" {
            return Err(RegistryError::Parsing {
                offset: abs_offset,
                reason: format!("Expected NK cell, got {:?}", cell_type_bytes),
            });
        }

        let nk_data_start = abs_offset + 6;
        let nk_data_end = nk_data_start + (cell_size.unsigned_abs() - 4) as usize;
        if nk_data_end > hive_data.len() {
            return Err(RegistryError::Parsing {
                offset: nk_data_start,
                reason: "NK record data truncated".to_string(),
            });
        }

        NkRecord::from_bytes(&hive_data[nk_data_start..nk_data_end])
    }
}

/// Navigate to a subkey by name (case-insensitive).
/// Returns an owned copy of the NK record.
pub fn find_subkey(nk: &NkRecord, hive_data: &[u8], hive_offset: usize, name: &str) -> Option<NkRecord> {
    for subkey in SubkeyIterator::new(nk, hive_data, hive_offset) {
        if let Ok(child) = subkey {
            if child.name.to_uppercase() == name.to_uppercase() {
                return Some(child);
            }
        }
    }
    None
}

/// Navigate a full path (e.g., "Software\\Microsoft\\Windows") from an NK record.
/// Returns an owned NK record at the end of the path, or None if any segment is missing.
pub fn navigate_path(
    start: &NkRecord,
    hive_data: &[u8],
    hive_offset: usize,
    path: &[&str],
) -> Option<NkRecord> {
    let mut current = start.clone();
    for segment in path {
        match find_subkey(&current, hive_data, hive_offset, segment) {
            Some(next) => current = next,
            None => return None,
        }
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_subkey_empty() {
        // NK with no subkeys
        let data = vec![0u8; 76];
        let nk = NkRecord::from_bytes(&data).unwrap();
        let hive_data = vec![0u8; 100];
        assert!(find_subkey(&nk, &hive_data, 0, "test").is_none());
    }
}
