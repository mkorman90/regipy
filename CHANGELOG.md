# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **REG_SZ and REG_EXPAND_SZ values decode the string when the data after its NUL terminator is not valid UTF-16** - the whole value failed the UTF-16 decode, so it fell back to UTF-8 or raw bytes. For example `TimeZoneKeyName` in the SYSTEM test hive came back as bytes, and as hex in the `timezone_data` and `timezone_data2` plugins, instead of `Eastern Standard Time`. The new `try_decode_string` returns the string before the terminator in that case, and the `regipy-rs` backend does the same

## [6.5.2] - 2026-10-17

### Fixed

- **`apply_transaction_logs` now applies transaction logs in sequence order and validates every entry** (gh #352)
  - The log with the earlier sequence chain is applied first, and a second log is only applied if its first entry continues the first log's last sequence number (N+1). Previously the caller's argument order decided, so the older log's stale pages could clobber newer ones (the UsrClass.dat test fixture lost 119 subkeys, the SYSTEM fixture 16)
  - Sequence continuity is enforced across the applied chain: recovery stops after entry N if N+1 does not follow, per the registry file format specification
  - Every entry's Marvin32 Hash-1/Hash-2 fields are verified (and the Hive bins data size must be a multiple of 4096 bytes); an invalid entry stops recovery and only the preceding entries are applied. A hash-valid entry whose declared page size exceeds its own data bounds is rejected at scan time
  - The restored hive now grows to the bin size an entry declares (bounded by 4096-byte alignment, the 32-bit addressable range, and the current hive size plus the log's own footprint) instead of failing with "points outside of the hive"
  - The restored hive header now records the last applied entry's sequence number as primary (and the preceding number as secondary), matching the spec's base-block state after the last applied entry
  - Test expectations for the SYSTEM and UsrClass.dat transaction-log fixtures were regenerated for the spec-correct order (previously locked counts were generated from the buggy order): SYSTEM 2507 → 2519, UsrClass 225 → 73. The NTUSER.DAT single-log case is unchanged
## [6.5.1] - 2026-10-15

### Fixed

- **Performance: resident (inline) values no longer trigger a read of the entire tail of the hive** (gh #350)
  - `NKRecord.read_value` passed the flagged `data_size` (≥ 0x80000000) straight to `stream.read()`, and since the hive stream is a `BytesIO` of the whole file, every resident value copied the tail of the hive into memory and discarded it (~46% of the values in NTUSER.DAT, 28% in Amcache.hve, 29% in SOFTWARE)
  - The read is now skipped for the types whose resident branches in `iter_values` rebuild the value from the VK `data_offset` field (`REG_NONE`/`REG_SZ`/`REG_EXPAND_SZ`/`REG_BINARY`/`REG_DWORD`/`REG_MULTI_SZ`/`REG_QWORD`); every other type keeps the original read, so output is byte-identical to earlier versions and to the `regipy-rs` backend
  - A full walk of the 36 MiB SOFTWARE test hive dropped from 400+s to ~5s

## [6.5.0] - 2026-10-11

### Security

- **Bounded memory and CPU usage when parsing untrusted hives and transaction logs**
  - `NKRecord._parse_indirect_block`: big-data ("db") value reassembly is now bounded by the db header's `number_of_segments`, the hive file size, and per-segment file bounds (mirroring the bounds `regipy-rs/src/parser.rs` already enforced). Previously, a crafted hive declaring a huge `data_size` with repeated segment offsets could amplify a small file into unbounded memory allocation
  - `apply_transaction_logs`: HvLE blocks with `log_size` smaller than the 40-byte block header (infinite re-parse loop), dirty-page entries pointing outside the primary hive (up to ~4 GiB restored-buffer ballooning, then written to disk), and DIRT dirty-page vectors shorter than the hive's `hbins_data_size` (raw `IndexError`) now raise `RegistryRecoveryException`
  - Behavior on valid hives and transaction logs is byte-identical; four new regression tests cover the crafted-input vectors
  - Reported by Zhang Yan <r0ck3t0615@gmail.com>

### Fixed

- **`shimcache` plugin on Windows Server 2003 / Vista / Server 2008 (NT5.2 format)** - every run crashed with `AttributeError: 'CacheEntryNt5' object has no attribute 'offsets'`, so no entries could be extracted from these SYSTEM hives (and `regipy-plugins-run` aborted unless `--continue-on-error` was set). Added regression tests for the 32-bit and 64-bit layouts

## [6.4.0] - 2026-07-25

### Added

- **`continue_on_error` flag** for `run_relevant_plugins()` and the `--continue-on-error` CLI option for `regipy-plugins-run` (fixes #338)
  - By default a failing plugin still aborts the run (original behavior preserved)
  - Set to `True` to log the failure, record it in the results, and continue with the remaining plugins
  - Plugin failures are always logged, regardless of the flag

### Changed

- **Type checking is now clean** - fixed all pre-existing mypy errors (the `type-check` CI job no longer needs `continue-on-error`)
- Added a `[tool.pyright]` configuration so the codebase is also clean under pyright strict; construct's incomplete type stubs are handled explicitly
- Corrected stale changelog version labels (the plugin/validation entry previously filed under 6.1.0 actually shipped in 6.2.0)

## [6.3.0] - 2026-07-18

### Added

- **Rust-accelerated core parser backend** (`regipy-rs`, alpha) - opt-in via `pip install regipy[rust]`, importable as `from regipy.registry_rs import RegistryHive`. Output parity with the Python backend is enforced by `regipy_tests/comparison_test.py`
- Benchmark tooling and `regipy-rs/BENCHMARKS.md`

### Changed

- Dependency and CI action bumps (click, libfwps-python, actions/*)

## [6.2.1] - 2026-01-22

### Added

- **MCP (Model Context Protocol) server** (`regipy_mcp_server/`) for natural-language registry forensics via Claude Desktop and other MCP-compatible clients

### Fixed

- Shellbags plugin: handle childless shellbag entries gracefully
- Various plugin bug fixes

## [6.2.0] - 2025-12-29

### Added

- **22 new plugins** covering additional forensic artifacts:
  - **NTUSER plugins**: `recentdocs`, `comdlg32`, `runmru`, `muicache`, `appkeys`, `sysinternals`, `putty`
  - **SOFTWARE plugins**: `app_paths`, `appinit_dlls`, `appcert_dlls`, `appcompat_flags`, `windows_defender`, `powershell_logging`, `execution_policy`, `networklist`
  - **SYSTEM plugins**: `usb_devices`, `mounted_devices`, `shares`, `pagefile`, `lsa_packages`, `pending_file_rename`
  - **SAM plugins**: `samparse` - Parses user accounts with login times, password info, account flags

- **Plugin validation system** - Plugins are now tracked for validation status
  - Validation status stored in `validated_plugins.json`, generated by the test framework and shipped with the package
  - `is_plugin_validated()` function to check validation status
  - Unvalidated plugins log a warning when executed

- **`--include-unvalidated` CLI flag** for `regipy-plugins-run` command
  - By default, only validated plugins are executed
  - Use this flag to include plugins that don't have validation test cases

- **`include_unvalidated` parameter** for `run_relevant_plugins()` function
  - Default: `False` (only validated plugins run)
  - Set to `True` to include unvalidated plugins

### Changed

- **Default plugin behavior**: Only validated plugins run by default. This is a safer default as unvalidated plugins may return incomplete or inaccurate data.
- Updated README with comprehensive plugin list organized by hive type
- Updated plugin validation documentation

## [6.1.0] - 2025-12-27

### Fixed

- Fixed missing `regipy.plugins.system.external` package in distribution
- Added tests to CI for better coverage
- Lint fixes

## [6.0.1] - 2025-12-26

### Breaking Changes

- **Minimum Python version raised to 3.9** - Dropped support for Python 3.6, 3.7, and 3.8
- **Removed `attrs` dependency** - All data classes (`Cell`, `VKRecord`, `LIRecord`, `Value`, `Subkey`) now use Python's built-in `dataclasses` module instead of `attrs`
  - If you used `attr.asdict()` on these classes, switch to `dataclasses.asdict()`
  - If you used `attr.fields()` or other attrs introspection, switch to `dataclasses.fields()`
- **Removed `setup.py`** - Package now uses `pyproject.toml` exclusively (PEP 517/518)

### Added

- `pyproject.toml` with full PEP 621 metadata
- `py.typed` marker for PEP 561 type checking support
- Pre-commit configuration with ruff and mypy hooks
- Consolidated CI workflow with test matrix for Python 3.9-3.13
- Development documentation in README

### Changed

- Migrated from `flake8` to `ruff` for linting and formatting
- Modernized Python syntax throughout codebase (f-strings, type hints, import sorting)
- Consolidated GitHub Actions workflows into unified `ci.yml` and `publish.yml`
- Updated all GitHub Actions to latest versions (v4/v5)

### Removed

- `setup.py` (replaced by `pyproject.toml`)
- `.flake8` configuration (replaced by ruff config in `pyproject.toml`)
- Legacy GitHub workflow files (`python-package.yml`, `python-publish.yml`, `tests.yml`)

## [5.2.0] and earlier

See [GitHub Releases](https://github.com/mkorman90/regipy/releases) for previous versions.
