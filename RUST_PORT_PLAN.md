# Rust Port Plan for regipy

## Overview

A Rust port of regipy's core functionality — the registry hive parser, transaction log recovery, and hive diffing. The plugin system and CLI are **out of scope** for v1.0 (they are Python-specific and highly domain-specific).

**Goals:**
- Zero-copy or minimal-copy parsing where feasible
- Safe Rust — no `unsafe` in the core parser
- Fast: significantly faster than the Python version
- Library-first: expose a clean Rust API; CLI is secondary
- FFI bindings (PyO3, C-FFI) optional later

---

## Architecture

```
regipy-rs/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API, re-exports
│   ├── hive.rs             # RegistryHive — entry point
│   ├── structs.rs          # Binary struct definitions (REGF, HBIN, NK, VK, etc.)
│   ├── cell.rs             # Cell parsing and iteration
│   ├── key.rs              # NKRecord — key navigation, subkeys, values
│   ├── value.rs            # Value parsing (REG_SZ, REG_BINARY, REG_DWORD, etc.)
│   ├── recovery.rs         # Transaction log application (HvLE + DIRT)
│   ├── diff.rs             # Hive comparison
│   ├── utils.rs            # Timestamp conversion, checksum, etc.
│   ├── errors.rs           # Custom error types
│   └── cli.rs              # CLI (optional, feature-gated)
├── tests/
│   └── integration.rs      # Tests against real hive files
└── examples/
    └── parse.rs            # Example usage
```

---

## Crate Structure (monorepo or separate crates?)

**Recommendation: single crate** (`regipy-rs`) with internal modules.
- Simplest to maintain
- No cross-crate overhead for what is a tight domain
- Can split later if needed (e.g., `regipy-rs-core` + `regipy-rs-cli`)

---

## Module-by-Module Mapping

### 1. `structs.rs` → Binary Struct Definitions

**Python:** `construct` library defines all binary structures declaratively.

**Rust:** Use `bytemuck` + `bitflags` for POD structs, or `binread`/`rmp` for declarative parsing.

**Recommendation: `binread` (from `rust-binsize` ecosystem) or manual `bytemuck` parsing.**

| Python (construct) | Rust equivalent |
|---|---|
| `REGF_HEADER` (4096 bytes) | `#[repr(C, packed)]` struct + `bytemuck::Pod` |
| `HBIN_HEADER` | Same |
| `CM_KEY_NODE` (76 bytes) | Same |
| `VALUE_KEY` (`vk` record) | Same |
| `TRANSACTION_LOG` (`HvLE`) | Same |
| `BIG_DATA_BLOCK` (`db`) | Same |
| `HASH_LEAF`, `FAST_LEAF`, `INDEX_LEAF` | Same |
| `INDEX_ROOT` (`ri`) | Same |
| `SECURITY_DESCRIPTOR`, `SID`, `ACL`, `ACE` | Same |
| `VALUE_TYPE_ENUM` | Rust `enum` with `u32` repr |

**Key struct sizes (must match exactly):**
- REGF header: 4096 bytes
- CM_KEY_NODE: 76 bytes
- Cell header: 4 bytes (size + type)
- HBIN header: 28 bytes

**Value types enum:**
```rust
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq)]
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
```

### 2. `registry.py` → `hive.rs` + `key.rs`

**RegistryHive** — the main entry point:
```rust
pub struct RegistryHive {
    header: RegfHeader,
    root: KeyNode,       // NKRecord for root
    stream: Arc<Mutex<Bytes>>,  // or use a memory-mapped file
    hive_type: Option<HiveType>,
    partial_hive_path: Option<String>,
}

impl RegistryHive {
    pub fn from_path(path: &Path) -> Result<Self, Error>;
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error>;
    pub fn get_key(&self, path: &str) -> Result<&KeyNode, Error>;
    pub fn recurse_subkeys(&self, as_json: bool) -> impl Iterator<Item = SubkeyEntry>;
    pub fn get_control_sets(&self, registry_path: &str) -> Vec<&KeyNode>;
    pub fn hive_type(&self) -> &HiveType;
}
```

**Key design decisions:**
- Use `memmap2` for zero-copy file mapping (or `mmap` crate)
- `KeyNode` holds a reference into the hive's byte buffer (not owned data)
- Iteration yields owned `SubkeyEntry` or borrowed `&KeyNode` depending on use case
- Path resolution: split on `\`, walk from root NK record

**NKRecord (KeyNode):**
```rust
pub struct KeyNode {
    header: CmKeyNode,
    name: String,        // ASCII or UTF-16-LE depending on KEY_COMP_NAME flag
    subkey_count: u32,
    values_count: u32,
    volatile_subkey_count: u32,
    last_modified: u64,  // FILETIME
    // ... other fields
}

impl KeyNode {
    pub fn iter_subkeys(&self) -> SubkeyIterator;
    pub fn iter_values(&self) -> ValueIterator;
    pub fn get_subkey(&self, name: &str) -> Option<&KeyNode>;
    pub fn get_value(&self, name: &str) -> Option<&Value>;
}
```

**HBin:**
```rust
pub struct HBin {
    header: HBinHeader,
    data_offset: usize,
}

impl HBin {
    pub fn iter_cells(&self, data: &[u8]) -> CellIterator;
}
```

### 3. `cell.rs` — Cell Parsing

```rust
#[derive(Debug, Clone, Copy)]
pub struct Cell {
    pub offset: usize,
    pub cell_type: CellType,
    pub size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CellType {
    Nk,  // Name Key
    Li,  // Leaf Index
    Lf,  // Fast Leaf
    Lh,  // Hash Leaf
    Ri,  // Root Index
    Vk,  // Value Key
    // ... etc
}
```

Cell iteration: negative size = allocated, positive = free. Skip free cells.

### 4. `value.rs` — Value Parsing

```rust
#[derive(Debug, Clone)]
pub struct Value {
    pub name: String,
    pub value: ValueData,
    pub value_type: ValueType,
    pub is_corrupted: bool,
}

#[derive(Debug, Clone)]
pub enum ValueData {
    None,
    Sz(String),
    ExpandSz(String),
    Binary(Vec<u8>),
    Dword(u32),
    Qword(u64),
    MultiSz(Vec<String>),
    FileTime(DateTime<Utc>),
    ResourceList(Vec<u8>),
    Unknown(Vec<u8>),
    // Inline data for large values (data_size >= 0x80000000)
    InlineData(Vec<u8>),
}
```

**Value parsing logic (mirrors Python `iter_values`):**
- REG_SZ / REG_EXPAND_SZ → decode UTF-16-LE, strip nulls
- REG_BINARY / REG_NONE → hex string or raw bytes
- REG_DWORD → little-endian u32 (or inline if data_size >= 0x80000000)
- REG_QWORD → little-endian u64
- REG_MULTI_SZ → null-separated UTF-16-LE strings
- REG_FILETIME → FILETIME → DateTime<Utc>
- Large values (> 0x3FD8) → check for `db` signature → parse BIG_DATA_BLOCK → read segments
- DEVPROP detection (data_type > 0xFFFF0000)
- Unknown type 0x200000 → skip

### 5. `recovery.rs` — Transaction Log Recovery

```rust
pub fn apply_transaction_logs(
    hive_path: &Path,
    primary_log_path: &Path,
    secondary_log_path: Option<&Path>,
) -> Result<(PathBuf, u64), Error>;
```

**Two log formats:**
1. **HvLE** (modern): Parse `TRANSACTION_LOG` struct, iterate dirty pages, write to hive
2. **DIRT** (legacy): Parse bitmap, read 512-byte pages from log, write to hive

**Key operations:**
- Read dirty page offsets from log
- Seek to `REGF_HEADER_SIZE + offset` in hive
- Overwrite with data from log
- Update sequence numbers at offsets 4 and 8
- Update hive_bins_data_size at offset 40

### 6. `diff.rs` — Hive Comparison

```rust
pub fn compare_hives(first: &Path, second: &Path) -> Result<Vec<HiveDifference>, Error>;

pub enum HiveDifference {
    NewSubkey { path: String, timestamp: u64, hive: HiveSide },
    ModifiedSubkey { path: String, first_ts: u64, second_ts: u64 },
    NewValue { path: String, name: String, value: String, hive: HiveSide },
    ModifiedValue { path: String, name: String, first_value: String, second_value: String },
    DifferentHiveBinSize { first: u32, second: u32 },
}
```

Algorithm mirrors Python:
1. SHA-1 hash comparison (fast fail)
2. Header comparison
3. Enumerate all subkeys + timestamps
4. Set operations for new/removed keys
5. For modified keys, compare value sets

### 7. `utils.rs` — Utilities

```rust
pub fn convert_wintime(filetime: u64) -> DateTime<Utc>;
pub fn calculate_xor32_checksum(data: &[u8]) -> u32;
pub fn calculate_sha1(path: &Path) -> String;
pub fn identify_hive_type(name: &str) -> HiveType;
pub fn try_decode_binary(data: &[u8]) -> String;
```

**Timestamp conversion:**
- FILETIME: 100-nanosecond intervals since 1601-01-01 UTC
- `chrono` crate for DateTime handling

**Hive type identification** (mirrors Python `identify_hive_type`):
```rust
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
```

### 8. `errors.rs` — Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Registry key not found: {0}")]
    KeyNotFound(String),

    #[error("Value not found: {0}")]
    ValueNotFound(String),

    #[error("Parsing error: {0}")]
    Parsing(String),

    #[error("Hive is dirty: sequence numbers don't match")]
    HiveDirty,

    #[error("Unidentified hive type: {0}")]
    UnidentifiedHive(String),

    #[error("Recovery error: {0}")]
    Recovery(String),

    #[error("Corrupted registry data at offset {0:x}")]
    Corrupted(usize),
}
```

---

## Dependencies

```toml
[dependencies]
bytemuck = { version = "1", features = ["derive"] }
chrono = { version = "0.4", features = ["serde"] }
sha1 = "0.10"
thiserror = "1"
memmap2 = "0.9"
bitflags = "2"
binread = "2"  # Optional: for declarative binary parsing
serde = { version = "1", features = ["derive"], optional = true }
serde_json = { version = "1", optional = true }

[dev-dependencies]
tempfile = "3"
criterion = "0.5"

[features]
default = []
cli = ["clap"]
json = ["serde", "serde_json"]
```

**Key dependency choices:**
- `bytemuck` — zero-copy struct interpretation (safe, `#[repr(C)]`)
- `chrono` — timestamp handling (replaces `datetime` + `pytz`)
- `memmap2` — zero-copy file mapping (replaces `open().read()`)
- `thiserror` — ergonomic error types
- `sha1` — SHA-1 for diff (replaces `hashlib.sha1`)
- `serde`/`serde_json` — optional JSON serialization

---

## API Design Decisions

### 1. Memory Model

**Option A: Memory-mapped file (recommended)**
```rust
let hive = RegistryHive::from_path("NTUSER.DAT")?;
// All key/value data is zero-copy, mapped from file
```

**Option B: Owned bytes**
```rust
let hive = RegistryHive::from_bytes(data)?;
// For in-memory hives, extracted transaction logs, etc.
```

Support both via `From` traits or separate constructors.

### 2. Iteration Model

```rust
// Borrowed iteration (no allocation)
for key in hive.iter_subkeys() {
    println!("{}", key.name());
}

// Owned iteration (for collecting)
let entries: Vec<SubkeyEntry> = hive.recurse_subkeys().collect();

// With values
for entry in hive.recurse_subkeys_with_values() {
    println!("{}: {} values", entry.path, entry.values.len());
}
```

### 3. Error Handling

- Use `Result<T, RegistryError>` everywhere
- `Option` for optional lookups (e.g., `get_subkey` returns `Option`)
- No panics in library code (only in `unwrap`/`expect` for internal invariants)

### 4. JSON Support (Optional Feature)

```rust
#[cfg(feature = "json")]
impl SubkeyEntry {
    pub fn to_json(&self) -> serde_json::Value { ... }
}
```

---

## Performance Optimizations

1. **Zero-copy parsing**: Use `memmap2` + `bytemuck` to avoid copying hive data
2. **Borrowed iterators**: `iter_subkeys()` returns `&KeyNode`, not owned data
3. **String interning**: For repeated key names (e.g., in deep trees), consider `string-interner`
4. **Parallel diff**: For hive comparison, subkey enumeration could be parallelized
5. **Streaming**: For large hives, don't load the entire file — use file mapping
6. **Avoid allocations in hot paths**: `get_key()` should not allocate unless necessary

**Target performance**: 5-10x faster than Python for typical hives.

---

## What's NOT in Scope (v1.0)

| Python Feature | Rust Status | Reason |
|---|---|---|
| Plugin system | Not ported | Python-specific, domain-specific logic |
| 75+ forensic plugins | Not ported | Each is a separate crate/module |
| CLI (click-based) | Optional rewrite | `clap` would be the Rust equivalent |
| MCP server | Not ported | Python-specific integration |
| Validation framework | Not ported | Python-specific test infrastructure |
| `cli_utils.py` helpers | Not ported | CLI-specific utilities |

**Rationale**: The plugin system is the bulk of regipy's value but is also the most Python-specific part. The Rust port should focus on the **core parsing engine** — the part that benefits most from Rust's performance and safety guarantees.

Plugins could be added later as:
- Rust crates that depend on `regipy-rs`
- A plugin DSL (e.g., TOML-based configuration)
- FFI-bound Python plugins that use the Rust core

---

## Implementation Phases

### Phase 1: Core Parser (MVP)
- [ ] `structs.rs` — All binary struct definitions
- [ ] `cell.rs` — Cell header parsing and iteration
- [ ] `hive.rs` — RegistryHive, HBin, file loading
- [ ] `key.rs` — NKRecord, subkey iteration (LF/LH/RI/LI)
- [ ] `value.rs` — VKRecord, value type parsing
- [ ] `utils.rs` — Timestamps, checksums, hive type identification
- [ ] `errors.rs` — Error types
- [ ] Basic tests with real hive files

### Phase 2: Full Navigation
- [ ] `get_key()` — Path-based key lookup
- [ ] `recurse_subkeys()` — Recursive traversal
- [ ] Control set support
- [ ] Partial hive path support
- [ ] Security descriptor parsing

### Phase 3: Recovery & Diff
- [ ] `recovery.rs` — HvLE transaction log parsing
- [ ] `recovery.rs` — DIRT legacy log parsing
- [ ] `diff.rs` — Hive comparison
- [ ] Transaction log application

### Phase 4: Polish
- [ ] JSON serialization (optional feature)
- [ ] CLI (optional feature, `clap`)
- [ ] Documentation and examples
- [ ] Benchmarking suite
- [ ] PyO3 bindings (optional)

---

## Testing Strategy

1. **Unit tests**: Each struct parser, each value type decoder
2. **Integration tests**: Real hive files from `regipy_tests/data/`
3. **Fuzzing**: `cargo-fuzz` on binary struct parsers
4. **Property tests**: Round-trip parsing (parse → serialize → parse)
5. **Regression tests**: Same test hives as Python, same expected outputs

**Test data**: Share the same `.xz` compressed hive files from `regipy_tests/data/`.

---

## FFI / Python Bindings (Future)

If desired, expose the Rust core to Python via:

```rust
// PyO3 bindings
#[pyclass]
pub struct PyRegistryHive {
    inner: RegistryHive,
}

#[pymethods]
impl PyRegistryHive {
    fn get_key(&self, path: &str) -> PyResult<PySubkey> { ... }
    fn recurse_subkeys(&self, as_json: bool) -> PyResult<Vec<PySubkeyEntry>> { ... }
}
```

This would allow Python code to use the Rust parser as a drop-in replacement:
```python
from regipy_rs import RegistryHive  # Rust-backed
```

---

## File Size Estimates

| Module | Lines (est.) | Complexity |
|---|---|---|
| `structs.rs` | ~400 | Low |
| `cell.rs` | ~150 | Low |
| `hive.rs` | ~500 | Medium |
| `key.rs` | ~600 | Medium |
| `value.rs` | ~500 | Medium |
| `recovery.rs` | ~400 | Medium |
| `diff.rs` | ~300 | Medium |
| `utils.rs` | ~200 | Low |
| `errors.rs` | ~100 | Low |
| `cli.rs` (optional) | ~300 | Low |
| **Total** | **~3,250** | |

Comparable to Python's ~2,500 lines of core code, but with better type safety and performance.
