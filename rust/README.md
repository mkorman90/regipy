# regipy — Rust acceleration

This directory contains the **optional Rust backend** for regipy. It's a
drop-in accelerator for the registry parser that activates only when:

```bash
pip install regipy[fast]      # installs the regipy-rs wheel
REGIPY_BACKEND=rust            # opts in at runtime
```

Without those, regipy works exactly as it always has — pure Python on top
of `construct`.

## What's in this directory

```
rust/
├── regipy-core/        Rust crate: REGF parser, hbin/cell walk, NK/VK
│                       records, lf/lh/li/ri subkey lists, type-aware
│                       value decoding (REG_SZ → strict UTF-16 fallback,
│                       REG_DWORD/QWORD, REG_MULTI_SZ → GreedyRange(CString)
│                       semantics, REG_FILETIME → ISO string, REG_BINARY/
│                       NONE → hex, big-data block reassembly, DEVPROP
│                       fallback, inline-value quirks). ~900 LOC.
├── regipy-py/          PyO3 bindings: builds the regipy-rs Python wheel.
├── regipy-bench/       Benchmark + cross-validation binaries (not shipped).
└── target/             Cargo build outputs (gitignored).
```

The Python-side activation lives in [regipy/_rust_backend.py](../regipy/_rust_backend.py)
— a soft monkey-patch that swaps out three methods on `regipy.registry.RegistryHive`:
`__init__` (attaches a Rust hive handle), `recurse_subkeys` (full walk goes
through Rust), `get_key` (path lookup goes through Rust, returns a
construct-parsed NKRecord at the resolved offset for header-shape
compatibility). Construct stays as the fallback and as the parser for the
single header on each NK.

## Build & test locally

```bash
# Build the wheel
cd rust/regipy-py
maturin build --release
pip install --force-reinstall ../target/wheels/regipy_rs-*.whl

# Verify byte-exact 1:1 parity across all small/medium test hives
PYTHONPATH=. python regipy_tests/parity/parity_check.py
# Expected output: "Summary: 7 hives, 48140 keys total, 0 divergences"

# Run the test suite under both backends
pytest regipy_tests/                                  # construct backend
REGIPY_BACKEND=rust pytest regipy_tests/              # rust backend
```

The parity harness (`regipy_tests/parity/parity_check.py`) walks every key
and every value of seven test hives twice (once per backend) and compares
byte-for-byte:

| Hive | Keys | Values |
|---|---:|---:|
| NTUSER.DAT | 1,812 | 4,094 |
| amcache.hve | 2,105 | 17,539 |
| NTUSER_BAGMRU.DAT | 6,279 | 15,912 |
| UsrClass.dat | 6,205 | 12,369 |
| ntuser_software_partial | 6,396 | 19,990 |
| SYSTEM_2 | 20,015 | 49,775 |
| NTUSER_with_winscp | 5,328 | 12,014 |
| **Total** | **48,140** | **131,693** |

Any divergence — a single tuple `(path, value_name, value_type, value,
last_modified)` that differs between the two backends — fails the harness
and blocks merges via the CI job. **This is the DFIR-grade contract.**

## Performance

Per-hive walk timings (Python `recurse_subkeys(as_json=True)`):

| Hive | Python | Rust | Speedup |
|---|---:|---:|---:|
| NTUSER.DAT | 110 ms | 24 ms | 4.6× |
| amcache.hve | 320 ms | 60 ms | 5.3× |
| NTUSER_BAGMRU | 2.3 s | 70 ms | 32× |
| UsrClass.dat | 380 ms | 50 ms | 7.6× |
| ntuser_software_partial | 760 ms | 90 ms | 8.4× |
| SYSTEM_2 | 12 s | 3.0 s | 4.0× |
| NTUSER_with_winscp | 700 ms | 60 ms | 11.7× |

Full pytest suite: **47 s → 7 s ≈ 6×**. The cProfile breakdown is in
[POC_RESULTS.md](POC_RESULTS.md).

## Bugs in regipy that the Rust port mirrors for parity

To stay byte-exact with the construct backend, `regipy-core` reproduces
several construct-path quirks that you may want to fix in a follow-up Python
patch. They're listed here so the Rust side can drop the workarounds when
the Python side is fixed.

### 1. Inline REG_SZ / REG_BINARY / REG_NONE return the `data_offset` integer

When `data_size`'s high bit is set (the "value is inline in the
data_offset field" marker), `regipy.registry.iter_values` returns the
**raw `vk.data_offset` integer** rather than decoding the inline 4-byte
data as a string or bytes. So a REG_SZ inline value with data_offset = 48
shows up as the int `48` rather than the character `"0"`. Plugins relying
on this typing inconsistency (a string field that's sometimes an int)
should be updated to handle both.

```python
# Python regipy:
if data_type in ["REG_SZ", "REG_EXPAND", "REG_EXPAND_SZ"]:
    if vk.data_size >= 0x80000000:
        actual_value = vk.data_offset    # the int, not bytes
```

### 2. REG_MULTI_SZ inline reads rest-of-file as garbage

`stream.read(vk.data_size)` on a `BytesIO` with `data_size = 0x80000000`
reads to end-of-stream (~hive bytes from the seek point). Python regipy
then parses that garbage with `GreedyRange(CString("utf-16-le"))`,
producing a list of nonsense UTF-16 strings (some real-looking, most
random). This isn't useful forensic data — it's an artifact of the
high-bit interpretation falling through the type table. The Rust path
mirrors it for parity.

### 3. REG_MULTI_SZ skips big-data block reassembly

For `data_size > 0x3FD8` with the `db` cell signature, regipy's REG_SZ /
REG_BINARY / REG_NONE branches reassemble the segments. **REG_MULTI_SZ
doesn't** — it parses the 8-byte `db` header bytes directly as a UTF-16
list, producing garbage. The Rust path mirrors this skip; if Python is
fixed to reassemble, Rust should follow.

### 4. `value_type` field is sometimes a string, sometimes an int

`data_type = str(vk.data_type)` for unknown enum values produces an
`EnumIntegerString` (str subclass with int repr). For DEVPROP types
(>0xFFFF0000), `data_type = VALUE_TYPE_ENUM.parse(...)` produces an
`EnumInteger` (int subclass). The result: `value.value_type` is a `str`
("REG_SZ", "131076", …) for non-DEVPROP and an `int` (17, 18, …) for
DEVPROP. The Rust binding emits the same int/str split. Plugins should
treat `value_type` as `Union[str, int]`.

### 5. Microsecond rounding artifacts in FILETIME

Python `wintime / 10` is a correctly-rounded multi-precision int-to-float
division producing the closest f64. The result is then normalized to an
int via round-half-to-even by `timedelta(microseconds=…)`. For 17-digit
FILETIMEs near 1.3e16, the f64 grid step is 2 — meaning the trailing
microsecond may round to the nearest *even* integer rather than the
strictly closer one. The Rust path mirrors this exactly so timestamps are
identical to the bit. (See `wintime_to_us` and `wintime_to_iso` in
[regipy-core/src/lib.rs](regipy-core/src/lib.rs).)

### 6. Datetime ISO format omits `.000000` when microseconds are zero

Python's `datetime.isoformat()` drops the fractional-seconds suffix when
microseconds == 0, producing `2006-06-21T00:00:00+00:00` rather than
`2006-06-21T00:00:00.000000+00:00`. Rust matches.

### 7. data_type 0x200000 values are silently skipped

`elif int(vk.data_type) == 0x200000: continue` — these values never
appear in `iter_values()` output. Reason is "research pending". Rust
mirrors.

### 8. Strict UTF-16 in REG_MULTI_SZ; lossy elsewhere

`GreedyRange(CString("utf-16-le"))` uses **strict** UTF-16 decode and
stops the entire iteration on the first decode failure. Other types use
`try_decode_binary` which falls through to UTF-8 and then hex. The Rust
path mirrors the strict-then-stop behavior for REG_MULTI_SZ.

## What's NOT in Rust

- Transaction log replay (`regipy.recovery.apply_transaction_logs`)
- Security descriptor parsing (`get_security_key_info`)
- Direct `NKRecord.iter_values` on standalone NK records (only the bulk
  `recurse_subkeys` path is routed through Rust; per-key iteration falls
  through to construct)
- The construct header for every NK record (one parse per NK; tests
  assert exact `dict(nk.header)` shape)

These either don't matter for the bulk-walk hot path, or live in code
where construct's exact output is part of the public API contract.

## CI

`.github/workflows/ci.yml` adds a `test-rust-backend` job that:
1. Builds the wheel via maturin.
2. Re-runs the test suite under `REGIPY_BACKEND=rust`.
3. Re-runs plugin validation under `REGIPY_BACKEND=rust`.
4. Runs the parity harness as a forensic safety gate.

`.github/workflows/publish-rust.yml` builds wheels via cibuildwheel/
maturin-action across linux (x86_64, aarch64, musl), macOS (x86_64,
arm64), and Windows (x86_64), then publishes to PyPI as `regipy-rs` on
tag `regipy-rs-v*`. Uses **abi3-py38** so a single wheel per (OS, arch)
covers Python 3.8+.

The existing `publish.yml` continues to publish the pure-Python `regipy`
package on every release exactly as before. It is **not** modified.
