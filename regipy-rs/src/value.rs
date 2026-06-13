/// Parsed registry value data.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueData {
    /// REG_NONE — no data type
    None,
    /// REG_SZ / REG_EXPAND_SZ — null-terminated string
    String(String),
    /// REG_BINARY / REG_NONE with binary data
    Bytes(Vec<u8>),
    /// REG_DWORD — 32-bit unsigned integer
    Dword(u32),
    /// REG_QWORD — 64-bit unsigned integer
    Qword(u64),
    /// REG_MULTI_SZ — null-separated string array
    MultiString(Vec<String>),
    /// REG_FILETIME — Windows FILETIME timestamp (ISO 8601 format)
    FileTime(String),
    /// Unknown or unsupported type — raw bytes
    Unknown(Vec<u8>),
}

impl ValueData {
    /// Convert to a displayable string representation.
    pub fn as_string(&self) -> String {
        match self {
            ValueData::None => String::new(),
            ValueData::String(s) => s.clone(),
            ValueData::Bytes(b) => {
                // Try to decode as hex
                b.iter().map(|x| format!("{:02x}", x)).collect()
            }
            ValueData::Dword(d) => d.to_string(),
            ValueData::Qword(q) => q.to_string(),
            ValueData::MultiString(parts) => parts.join(", "),
            ValueData::FileTime(s) => s.clone(),
            ValueData::Unknown(b) => {
                b.iter().map(|x| format!("{:02x}", x)).collect()
            }
        }
    }

    /// Check if the value is empty / has no meaningful data.
    pub fn is_empty(&self) -> bool {
        match self {
            ValueData::None => true,
            ValueData::String(s) => s.is_empty(),
            ValueData::Bytes(b) => b.is_empty(),
            ValueData::Dword(_) => false,
            ValueData::Qword(_) => false,
            ValueData::MultiString(v) => v.is_empty(),
            ValueData::FileTime(_) => false,
            ValueData::Unknown(b) => b.is_empty(),
        }
    }
}

/// A parsed registry value with its name, type, and data.
#[derive(Debug, Clone)]
pub struct Value {
    pub name: String,
    pub value: ValueData,
    pub value_type: u32,
    pub is_corrupted: bool,
}

/// A list of parsed values.
#[derive(Debug, Clone, Default)]
pub struct ValueList(pub Vec<Value>);

impl ValueList {
    pub fn new() -> Self {
        ValueList(Vec::new())
    }

    pub fn push(&mut self, value: Value) {
        self.0.push(value);
    }
}

#[cfg(feature = "json")]
impl Value {
    /// Serialize to a JSON-compatible serde_json::Value.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "type": self.value_type,
            "value": self.value.as_string(),
            "is_corrupted": self.is_corrupted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_data_as_string() {
        assert_eq!(ValueData::String("hello".to_string()).as_string(), "hello");
        assert_eq!(ValueData::Dword(42).as_string(), "42");
        assert_eq!(ValueData::Qword(12345).as_string(), "12345");
        assert_eq!(
            ValueData::Bytes(vec![0x48, 0x69]).as_string(),
            "4869"
        );
        assert_eq!(ValueData::None.as_string(), "");
    }

    #[test]
    fn test_value_data_is_empty() {
        assert!(ValueData::None.is_empty());
        assert!(ValueData::String(String::new()).is_empty());
        assert!(ValueData::Bytes(Vec::new()).is_empty());
        assert!(!ValueData::Dword(0).is_empty());
        assert!(!ValueData::Qword(0).is_empty());
        assert!(ValueData::MultiString(Vec::new()).is_empty());
        assert!(!ValueData::String("hello".to_string()).is_empty());
        assert!(!ValueData::Dword(1).is_empty());
    }
}
