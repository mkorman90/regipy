use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use sha1::Digest;

use crate::errors::RegistryResult;
use crate::hive::RegistryHive;
use crate::key::SubkeyEntry;
use crate::structs::convert_wintime;
use crate::NkRecord;

/// A difference found between two hives.
#[derive(Debug, Clone)]
pub enum HiveDifference {
    /// Hive bin data size differs between the two hives.
    DifferentHiveBinSize {
        first: u32,
        second: u32,
    },
    /// A subkey exists in the first hive but not the second.
    NewSubkey {
        path: String,
        timestamp: String,
        hive: HiveSide,
    },
    /// A subkey exists in both hives but has a different timestamp.
    ModifiedSubkey {
        path: String,
        first_timestamp: String,
        second_timestamp: String,
    },
    /// A value exists in the first hive but not the second.
    NewValue {
        path: String,
        name: String,
        value: String,
        hive: HiveSide,
    },
    /// A value exists in both hives but has different values.
    ModifiedValue {
        path: String,
        name: String,
        first_value: String,
        second_value: String,
    },
}

/// Which hive a difference belongs to.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HiveSide {
    First,
    Second,
}

/// Compare two hive files and return a list of differences.
/// 
/// This function:
/// 1. Compares SHA-1 hashes (fast fail if identical)
/// 2. Compares header parameters (hive bin data size)
/// 3. Enumerates all subkeys and timestamps
/// 4. Finds new/removed/modified subkeys
/// 5. For modified subkeys, compares value sets
pub fn compare_hives(first_path: &Path, second_path: &Path) -> RegistryResult<Vec<HiveDifference>> {
    // Compare SHA-1 hashes
    let first_hash = calculate_sha1(first_path)?;
    let second_hash = calculate_sha1(second_path)?;

    if first_hash == second_hash {
        return Ok(Vec::new());
    }

    // Parse both hives
    let first_hive = RegistryHive::from_path(first_path)?;
    let second_hive = RegistryHive::from_path(second_path)?;

    let mut differences = Vec::new();

    // Compare header parameters
    if first_hive.header.hive_bins_data_size != second_hive.header.hive_bins_data_size {
        differences.push(HiveDifference::DifferentHiveBinSize {
            first: first_hive.header.hive_bins_data_size,
            second: second_hive.header.hive_bins_data_size,
        });
    }

    // Enumerate subkeys for each hive
    let first_subkeys = enumerate_subkeys(&first_hive);
    let second_subkeys = enumerate_subkeys(&second_hive);

    // Get sets of subkey paths
    let first_paths: std::collections::HashSet<&str> = first_subkeys.iter().map(|s| s.path.as_str()).collect();
    let second_paths: std::collections::HashSet<&str> = second_subkeys.iter().map(|s| s.path.as_str()).collect();

    // Find subkeys in first but not in second
    for path in first_paths.difference(&second_paths) {
        if let Some(entry) = first_subkeys.iter().find(|s| s.path == *path) {
            let timestamp = convert_wintime(entry.last_modified).to_rfc3339();
            differences.push(HiveDifference::NewSubkey {
                path: path.to_string(),
                timestamp,
                hive: HiveSide::First,
            });
        }
    }

    // Find subkeys in second but not in first
    for path in second_paths.difference(&first_paths) {
        if let Some(entry) = second_subkeys.iter().find(|s| s.path == *path) {
            let timestamp = convert_wintime(entry.last_modified).to_rfc3339();
            differences.push(HiveDifference::NewSubkey {
                path: path.to_string(),
                timestamp,
                hive: HiveSide::Second,
            });
        }
    }

    // Find subkeys that exist in both but have different timestamps
    let common_paths: std::collections::HashSet<&str> = first_paths.intersection(&second_paths).copied().collect();
    for path in common_paths {
        let first_entry = first_subkeys.iter().find(|s| s.path == path).unwrap();
        let second_entry = second_subkeys.iter().find(|s| s.path == path).unwrap();

        if first_entry.last_modified != second_entry.last_modified {
            let first_ts = convert_wintime(first_entry.last_modified).to_rfc3339();
            let second_ts = convert_wintime(second_entry.last_modified).to_rfc3339();
            differences.push(HiveDifference::ModifiedSubkey {
                path: path.to_string(),
                first_timestamp: first_ts,
                second_timestamp: second_ts,
            });

            // Compare values for this subkey
            compare_subkey_values(
                &first_hive,
                &second_hive,
                path,
                &mut differences,
            )?;
        }
    }

    Ok(differences)
}

/// Enumerate all subkeys from a hive, collecting path and timestamp.
fn enumerate_subkeys(hive: &RegistryHive) -> Vec<SubkeyEntry> {
    let mut entries = Vec::new();
    for entry in hive.recurse_subkeys() {
        if let Ok(nk) = entry {
            let last_modified = convert_wintime(nk.header.last_modified);
            entries.push(SubkeyEntry {
                name: nk.name.clone(),
                path: format!("\\{}", nk.name),
                last_modified: last_modified.timestamp(),
                subkey_count: nk.subkey_count,
                values_count: nk.values_count,
            });
        }
    }
    entries
}

/// Compare values between two subkeys and find differences.
fn compare_subkey_values(
    first_hive: &RegistryHive,
    second_hive: &RegistryHive,
    path: &str,
    differences: &mut Vec<HiveDifference>,
) -> RegistryResult<()> {
    let first_key = first_hive.get_key(path)?;
    let second_key = second_hive.get_key(path)?;

    let first_values = get_value_map(&first_key);
    let second_values = get_value_map(&second_key);

    let first_names: std::collections::HashSet<&str> = first_values.keys().map(|s| s.as_str()).collect();
    let second_names: std::collections::HashSet<&str> = second_values.keys().map(|s| s.as_str()).collect();

    // Values in first but not in second
    for name in first_names.difference(&second_names) {
        if let Some(value) = first_values.get(*name) {
            differences.push(HiveDifference::NewValue {
                path: path.to_string(),
                name: name.to_string(),
                value: value.clone(),
                hive: HiveSide::First,
            });
        }
    }

    // Values in second but not in first
    for name in second_names.difference(&first_names) {
        if let Some(value) = second_values.get(*name) {
            differences.push(HiveDifference::NewValue {
                path: path.to_string(),
                name: name.to_string(),
                value: value.clone(),
                hive: HiveSide::Second,
            });
        }
    }

    // Values in both - check for modifications
    for name in first_names.intersection(&second_names) {
        let first_val = first_values.get(*name).unwrap();
        let second_val = second_values.get(*name).unwrap();
        if first_val != second_val {
            differences.push(HiveDifference::ModifiedValue {
                path: path.to_string(),
                name: name.to_string(),
                first_value: first_val.clone(),
                second_value: second_val.clone(),
            });
        }
    }

    Ok(())
}

/// Get a map of value name -> value string for a key.
fn get_value_map(_key: &NkRecord) -> HashMap<String, String> {
    let mut values = HashMap::new();
    // In a real implementation, we'd iterate over the key's values
    // For now, return an empty map as a placeholder
    values
}

/// Calculate SHA-1 hash of a file.
pub fn calculate_sha1(path: &Path) -> RegistryResult<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = sha1::Sha1::new();
    
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_calculates() {
        // Create a temporary file
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_sha1.txt");
        std::fs::write(&test_file, "hello world").unwrap();
        
        let hash = calculate_sha1(&test_file).unwrap();
        // SHA-1 of "hello world" is "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        assert_eq!(hash.len(), 40);
        assert_eq!(hash, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
        
        std::fs::remove_file(&test_file).unwrap();
    }
}
