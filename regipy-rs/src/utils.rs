use crate::errors::RegistryResult;

/// Calculate SHA-1 hash of a file.
pub fn calculate_sha1(path: &std::path::Path) -> RegistryResult<String> {
    use std::io::Read;
    use sha1::Digest;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha1::Sha1::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Calculate XOR-32 checksum over a buffer (must be multiple of 4 bytes).
pub fn calculate_xor32_checksum(data: &[u8]) -> RegistryResult<u32> {
    if data.len() % 4 != 0 {
        return Err(crate::errors::RegistryError::Parsing {
            offset: 0,
            reason: format!("Buffer length {} is not a multiple of 4", data.len()),
        });
    }
    let mut checksum: u32 = 0;
    for chunk in data.chunks_exact(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
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

/// Trim a string for error messages.
pub fn trim_for_error(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!(
            "{}... (trimmed from {} chars)",
            &s[..max_len],
            s.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha1() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello world").unwrap();
        let hash = calculate_sha1(tmp.path()).unwrap();
        // SHA-1 of "hello world" is 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
        assert_eq!(hash, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    }

    #[test]
    fn test_calculate_xor32_checksum() {
        // Big-endian byte order (matching Python)
        let data = b"\x01\x02\x03\x04\x05\x06\x07\x08";
        let checksum = calculate_xor32_checksum(data).unwrap();
        assert_eq!(checksum, 0x04030201 ^ 0x08070605);
    }

    #[test]
    fn test_try_decode_binary_utf16() {
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
    fn test_trim_for_error() {
        assert_eq!(trim_for_error("short", 10), "short");
        let long = "a".repeat(100);
        let trimmed = trim_for_error(&long, 20);
        assert!(trimmed.starts_with("a"));
        assert!(trimmed.contains("..."));
        assert!(trimmed.contains("100"));
    }
}
