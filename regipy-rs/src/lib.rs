//! # regipy-rs
//!
//! Fast, safe Windows registry hive parser.
//!
//! This crate provides a zero-copy parser for Windows registry hive files
//! (`.hive`, `.dat`, `.LOG` files with the REGF header). It supports:
//!
//! - Parsing REGF headers and HBIN blocks
//! - Navigating key trees (NK records)
//! - Reading values (VK records) of all standard types
//! - Recursive subkey traversal
//! - Hive type identification
//! - Transaction log recovery (HvLE and DIRT formats)
//! - Hive comparison/diffing
//!
//! # Example
//!
//! ```no_run
//! use regipy_rs::RegistryHive;
//!
//! // Load a hive file
//! let hive = RegistryHive::from_path(std::path::Path::new("test_hive.hive")).unwrap();
//!
//! // Navigate to a key
//! let key = hive.get_key("Software\\Microsoft\\Windows").unwrap();
//! println!("Key: {}, {} values", key.name, key.values_count);
//!
//! // Iterate all subkeys
//! for entry in hive.recurse_subkeys() {
//!     let nk = entry.unwrap();
//!     println!("{} ({} subkeys)", nk.name, nk.subkey_count);
//! }
//! ```

pub mod cell;
pub mod errors;
pub mod hive;
pub mod key;
pub mod structs;
pub mod utils;
pub mod value;

pub use cell::{CellHeader, CellType, NkRecord};
pub use errors::{RegistryError, RegistryResult};
pub use hive::{CellIterator, RegistryHive};
pub use key::{find_subkey, navigate_path, SubkeyEntry, SubkeyIterator};
pub use structs::*;
pub use value::{Value, ValueData, ValueList};

// Re-export commonly used types for convenience
pub use chrono::DateTime;
pub use structs::HiveType;
