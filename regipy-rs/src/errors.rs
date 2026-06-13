use std::io;

/// All errors for registry parsing operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Registry key not found: {0}")]
    KeyNotFound(String),

    #[error("Value not found: {0}")]
    ValueNotFound(String),

    #[error("Parsing error at offset 0x{offset:x}: {reason}")]
    Parsing { offset: usize, reason: String },

    #[error("Hive is dirty: primary ({primary}) != secondary ({secondary}) sequence numbers")]
    HiveDirty { primary: u32, secondary: u32 },

    #[error("Unidentified hive type: {0}")]
    UnidentifiedHive(String),

    #[error("Corrupted registry data at offset 0x{0:x}")]
    Corrupted(usize),

    #[error("Value data too large to parse inline")]
    ValueTooLarge,

    #[error("Transaction log error: {0}")]
    TransactionLog(String),
}

/// Result type alias for registry operations.
pub type RegistryResult<T> = Result<T, RegistryError>;
