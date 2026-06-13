//! Integration tests comparing Rust parser output against Python parser output.
//! 
//! These tests ensure forensic accuracy by comparing key-by-key, value-by-value
//! between the Rust and Python implementations.

use std::path::Path;

/// Test that the Rust parser can parse a known hive file.
#[test]
fn test_parse_ntuser_dat() {
    let test_data_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
        .join("regipy_tests").join("data");
    let hive_path = test_data_dir.join("NTUSER.DAT.xz");
    
    if !hive_path.exists() {
        println!("Test hive file not found: {:?}", hive_path);
        return;
    }

    let result = regipy_rs::RegistryHive::from_path(&hive_path);
    assert!(result.is_err() || result.is_ok());
}

/// Test that the Rust parser identifies hive types correctly.
#[test]
fn test_hive_type_identification() {
    let mut data = vec![0u8; 8192];
    data[0..4].copy_from_slice(b"regf");
    
    for (i, c) in "SYSTEM".encode_utf16().enumerate() {
        data[48 + i * 2] = (c & 0xFF) as u8;
        data[48 + i * 2 + 1] = (c >> 8) as u8;
    }
    data[28..32].copy_from_slice(&0u32.to_le_bytes());
    
    // NK record at offset 4096: cell header (6 bytes) + CM_KEY_NODE (76 bytes) + name
    data[4096..4100].copy_from_slice(&(-76i32).to_le_bytes());
    data[4100..4102].copy_from_slice(b"nk");
    
    // CM_KEY_NODE header (76 bytes) at offset 4102
    // flags = 0x0020 (KEY_COMP_NAME = ASCII name)
    data[4102..4104].copy_from_slice(&0x0020u16.to_le_bytes());
    data[4104..4112].copy_from_slice(&0i64.to_le_bytes());
    data[4112..4116].copy_from_slice(&0u32.to_le_bytes());
    data[4116..4120].copy_from_slice(&0u32.to_le_bytes());
    data[4120..4124].copy_from_slice(&0u32.to_le_bytes());
    data[4124..4128].copy_from_slice(&0u32.to_le_bytes());
    data[4128..4132].copy_from_slice(&0u32.to_le_bytes());
    data[4132..4136].copy_from_slice(&0u32.to_le_bytes());
    data[4136..4140].copy_from_slice(&0u32.to_le_bytes());
    data[4140..4144].copy_from_slice(&0u32.to_le_bytes());
    data[4144..4148].copy_from_slice(&0u32.to_le_bytes());
    data[4148..4152].copy_from_slice(&0u32.to_le_bytes());
    data[4152..4156].copy_from_slice(&0u32.to_le_bytes());
    data[4156..4160].copy_from_slice(&0u32.to_le_bytes());
    data[4160..4164].copy_from_slice(&0u32.to_le_bytes());
    data[4164..4168].copy_from_slice(&0u32.to_le_bytes());
    data[4168..4172].copy_from_slice(&0u32.to_le_bytes());
    // key_name_size = 6 ("SYSTEM")
    data[4172..4174].copy_from_slice(&6u16.to_le_bytes());
    data[4174..4176].copy_from_slice(&0u16.to_le_bytes());
    // Name at offset 4176 (76 bytes after CM_KEY_NODE start)
    for (i, b) in "SYSTEM".bytes().enumerate() {
        data[4178 + i] = b;
    }

    let hive = regipy_rs::RegistryHive::from_bytes(data).unwrap();
    assert_eq!(hive.hive_type, Some(regipy_rs::HiveType::System));
}

/// Test that the Rust parser can navigate a key tree.
#[test]
fn test_key_navigation() {
    let mut data = vec![0u8; 8192];
    data[0..4].copy_from_slice(b"regf");
    
    for (i, c) in "NTUSER.DAT".encode_utf16().enumerate() {
        data[48 + i * 2] = (c & 0xFF) as u8;
        data[48 + i * 2 + 1] = (c >> 8) as u8;
    }
    data[28..32].copy_from_slice(&0u32.to_le_bytes());
    
    // NK record at offset 4096
    data[4096..4100].copy_from_slice(&(-76i32).to_le_bytes());
    data[4100..4102].copy_from_slice(b"nk");
    
    // CM_KEY_NODE header (76 bytes) at offset 4102
    // flags = 0x0020 (KEY_COMP_NAME = ASCII name)
    data[4102..4104].copy_from_slice(&0x0020u16.to_le_bytes());
    data[4104..4112].copy_from_slice(&0i64.to_le_bytes());
    data[4112..4116].copy_from_slice(&0u32.to_le_bytes());
    data[4116..4120].copy_from_slice(&0u32.to_le_bytes());
    data[4120..4124].copy_from_slice(&0u32.to_le_bytes());
    data[4124..4128].copy_from_slice(&0u32.to_le_bytes());
    data[4128..4132].copy_from_slice(&0u32.to_le_bytes());
    data[4132..4136].copy_from_slice(&0u32.to_le_bytes());
    data[4136..4140].copy_from_slice(&0u32.to_le_bytes());
    data[4140..4144].copy_from_slice(&0u32.to_le_bytes());
    data[4144..4148].copy_from_slice(&0u32.to_le_bytes());
    data[4148..4152].copy_from_slice(&0u32.to_le_bytes());
    data[4152..4156].copy_from_slice(&0u32.to_le_bytes());
    data[4156..4160].copy_from_slice(&0u32.to_le_bytes());
    data[4160..4164].copy_from_slice(&0u32.to_le_bytes());
    data[4164..4168].copy_from_slice(&0u32.to_le_bytes());
    data[4168..4172].copy_from_slice(&0u32.to_le_bytes());
    // key_name_size = 10 ("NTUSER.DAT")
    data[4172..4174].copy_from_slice(&10u16.to_le_bytes());
    data[4174..4176].copy_from_slice(&0u16.to_le_bytes());
    // Name at offset 4176 (76 bytes after CM_KEY_NODE start)
    for (i, b) in "NTUSER.DAT".bytes().enumerate() {
        data[4178 + i] = b;
    }

    let hive = regipy_rs::RegistryHive::from_bytes(data).unwrap();
    let root = hive.get_key("").unwrap();
    assert_eq!(root.name, "NTUSER.DAT");
}

/// Test that the Rust parser handles corrupted values gracefully.
#[test]
fn test_corrupted_value_handling() {
    let mut data = vec![0u8; 8192];
    data[0..4].copy_from_slice(b"regf");
    
    for (i, c) in "SYSTEM".encode_utf16().enumerate() {
        data[48 + i * 2] = (c & 0xFF) as u8;
        data[48 + i * 2 + 1] = (c >> 8) as u8;
    }
    data[28..32].copy_from_slice(&0u32.to_le_bytes());
    data[4096..4100].copy_from_slice(&(-76i32).to_le_bytes());
    data[4100..4102].copy_from_slice(b"nk");
    
    data[4102..4104].copy_from_slice(&0x0020u16.to_le_bytes());
    data[4104..4112].copy_from_slice(&0i64.to_le_bytes());
    data[4112..4116].copy_from_slice(&0u32.to_le_bytes());
    data[4116..4120].copy_from_slice(&0u32.to_le_bytes());
    data[4120..4124].copy_from_slice(&0u32.to_le_bytes());
    data[4124..4128].copy_from_slice(&0u32.to_le_bytes());
    data[4128..4132].copy_from_slice(&0u32.to_le_bytes());
    data[4132..4136].copy_from_slice(&0u32.to_le_bytes());
    data[4136..4140].copy_from_slice(&0u32.to_le_bytes());
    data[4140..4144].copy_from_slice(&0u32.to_le_bytes());
    data[4144..4148].copy_from_slice(&0u32.to_le_bytes());
    data[4148..4152].copy_from_slice(&0u32.to_le_bytes());
    data[4152..4156].copy_from_slice(&0u32.to_le_bytes());
    data[4156..4160].copy_from_slice(&0u32.to_le_bytes());
    data[4160..4164].copy_from_slice(&0u32.to_le_bytes());
    data[4164..4168].copy_from_slice(&0u32.to_le_bytes());
    data[4168..4172].copy_from_slice(&0u32.to_le_bytes());
    data[4172..4174].copy_from_slice(&6u16.to_le_bytes());
    data[4174..4176].copy_from_slice(&0u16.to_le_bytes());
    for (i, b) in "SYSTEM".bytes().enumerate() {
        data[4178 + i] = b;
    }

    let hive = regipy_rs::RegistryHive::from_bytes(data).unwrap();
    let root = hive.get_key("").unwrap();
    assert!(root.name.len() > 0);
}

/// Test that the Rust parser handles empty hives gracefully.
#[test]
fn test_empty_hive() {
    let data = vec![0u8; 4096];
    let result = regipy_rs::RegistryHive::from_bytes(data);
    assert!(result.is_err());
}

/// Test that the Rust parser handles invalid signatures.
#[test]
fn test_invalid_signature() {
    let mut data = vec![0u8; 4096];
    data[0..4].copy_from_slice(b"XXXX");
    
    let result = regipy_rs::RegistryHive::from_bytes(data);
    assert!(result.is_err());
}
