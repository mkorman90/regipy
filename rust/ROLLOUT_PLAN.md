# Rust acceleration rollout plan

> Goal: keep all of regipy's plugins, CLI, and public API in Python.
> Replace the construct-based parser with a Rust core (`regipy_rs`) that
> ships as an **opt-in** wheel. Mainstream `pip install regipy` continues to
> work unchanged.

## Architecture target

```
┌──────────────────────────────────────────────────────────┐
│  regipy (Python)                                         │
│  ┌────────────────────────────────────────────────────┐  │
│  │  Plugins, CLI, MCP server, regdiff, recovery, ...  │  │  ← unchanged
│  └────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────┐  │
│  │  regipy.registry (RegistryHive, NKRecord, Value)   │  │
│  │  ┌────────────────┐    ┌────────────────────────┐  │  │
│  │  │ Construct      │    │ Rust-backed            │  │  │
│  │  │ implementation │ OR │ implementation (opt-in)│  │  │  ← swap layer
│  │  │ (current)      │    │ via regipy_rs PyO3     │  │  │
│  │  └────────────────┘    └────────────────────────┘  │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │  regipy_rs (PyO3 wheel) │
                 └─────────────────────────┘
                              │
                              ▼
                 ┌─────────────────────────┐
                 │  regipy-core (Rust crate)│
                 └─────────────────────────┘
```

`pip install regipy` → pure Python, slow but works everywhere.
`pip install regipy[fast]` → installs `regipy-rs` wheel, transparently
faster.

## Compatibility contract

The Rust-backed `RegistryHive` must be **byte-exact** with the construct
implementation on:

1. `walk_stats()` (recursive key/value counts) ✓ already validated on 4 hives.
2. `recurse_subkeys()` output: same Subkey/Value dataclass shape, same field
   types, same iteration order, same path strings.
3. `get_key()`, `get_value()`, `iter_subkeys()`, `iter_values()`.
4. Value type decoding (REG_SZ, REG_DWORD, REG_MULTI_SZ, REG_QWORD,
   REG_BINARY, REG_FILETIME, REG_EXPAND_SZ).
5. Edge cases: ASCII vs UTF-16 names, lf/lh/li/ri, big data blocks (`db`),
   inline values (high bit set in data_size).
6. Exception types: `RegistryKeyNotFoundException`,
   `RegistryParsingException`, etc. — Rust raises the same Python exceptions.

A pytest matrix runs the existing test suite with both backends. Anything
that diverges blocks merge.

## Phased rollout

### Phase 1 — POC (DONE)

- [x] `regipy-core` crate: REGF, hbin, cells, NK, VK, lf/lh/li/ri.
- [x] Path-by-path correctness vs Python on 4 hives.
- [x] `regipy_rs` PyO3 binding: `RegistryHive`, `recurse_subkeys`,
      `walk_stats`.
- [x] Benchmarks documented in [POC_RESULTS.md](POC_RESULTS.md).

### Phase 2 — feature parity

- [ ] VK type decoding in Rust matching `regipy.registry.iter_values`:
  - `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD`,
    `REG_BINARY`, `REG_NONE`, `REG_FILETIME`, `REG_LINK`,
    `REG_RESOURCE_LIST`, `REG_RESOURCE_REQUIREMENTS_LIST`,
    `REG_FULL_RESOURCE_DESCRIPTOR`.
  - DEVPROP fallback (data_type > 0xFFFF0000).
  - Inline values (data_size high bit).
  - Big data block (`db`) reassembly.
- [ ] Security descriptors (sk records), SID, ACL, ACE.
- [ ] Class names.
- [ ] `get_control_sets()`.
- [ ] Partial hive support (`partial_hive_path`).
- [ ] Hive type identification.
- [ ] Map Rust errors to existing Python exception classes.

### Phase 3 — backend swap

- [ ] Add `regipy.registry._fast` shim that imports `regipy_rs` on demand.
- [ ] Modify `regipy.registry.RegistryHive.__new__` (or factory) to return
      a Rust-backed instance when available, else fall back to construct.
- [ ] All public types (`Subkey`, `Value`, `NKRecord`) unchanged.
- [ ] `regipy_rs` wheel built abi3 so a single wheel covers Python 3.8+.
- [ ] `pyproject.toml` extra: `regipy[fast] = ["regipy-rs == X.Y.Z"]`.

### Phase 4 — transaction logs

- [ ] Port `apply_transaction_logs` to Rust.
- [ ] `regipy-process-transaction-logs` CLI keeps its Python entry point but
      calls into Rust.

### Phase 5 — CLI tools (optional)

- [ ] `regipy-dump`: thin Python wrapper, walks via Rust, prints JSON.
- [ ] `regipy-diff`: walk both hives in Rust, diff in Python (or Rust).
- [ ] `regipy-plugins-run`: unchanged — plugins call Python `RegistryHive`
      which is now Rust-backed.

### Phase 6 — community

- [ ] Update README explaining `[fast]` extra and what it changes.
- [ ] Blog post.
- [ ] Track perf regressions with a CI bench (pinned hive, fail if
      slowdown > 2× from a baseline).

## Distribution & CI

### Wheel build

Use **maturin + cibuildwheel** to produce abi3 wheels. abi3 (`py38+`) means
**one wheel per (OS, arch)** covers all CPython versions ≥ 3.8.

Targets:

| OS | Arch | Builder |
|----|------|---------|
| Linux (manylinux_2_17) | x86_64 | GitHub-hosted `ubuntu-latest` |
| Linux (manylinux_2_17) | aarch64 | `ubuntu-24.04-arm` (or QEMU on x86_64) |
| Linux (musllinux_1_2) | x86_64 | cibuildwheel |
| macOS | x86_64 | `macos-13` |
| macOS | arm64 | `macos-14` (Apple Silicon) |
| Windows | x86_64 | `windows-latest` |
| Windows | arm64 | optional (low DFIR demand) |

That's 6–7 wheels per release. cibuildwheel handles the matrix.

### Proposed `.github/workflows/release.yml`

```yaml
name: Release regipy-rs

on:
  push:
    tags: ["v*"]
  workflow_dispatch:

jobs:
  build-wheels:
    name: ${{ matrix.os }} (${{ matrix.target }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        include:
          - { os: ubuntu-latest,    target: x86_64-unknown-linux-gnu,    abi: manylinux2014, name: linux-x86_64 }
          - { os: ubuntu-24.04-arm, target: aarch64-unknown-linux-gnu,   abi: manylinux2014, name: linux-aarch64 }
          - { os: ubuntu-latest,    target: x86_64-unknown-linux-musl,   abi: musllinux_1_2, name: linux-musl-x86_64 }
          - { os: macos-13,         target: x86_64-apple-darwin,         abi: macosx_10_12,  name: macos-x86_64 }
          - { os: macos-14,         target: aarch64-apple-darwin,        abi: macosx_11_0,   name: macos-arm64 }
          - { os: windows-latest,   target: x86_64-pc-windows-msvc,      abi: win_amd64,     name: windows-x86_64 }

    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - name: Build wheel
        uses: PyO3/maturin-action@v1
        with:
          working-directory: rust/regipy-py
          target: ${{ matrix.target }}
          args: --release --out dist --strip
          manylinux: ${{ matrix.abi == 'manylinux2014' && '2014' || 'auto' }}
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: wheels-${{ matrix.name }}
          path: rust/regipy-py/dist/*.whl

  build-sdist:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: PyO3/maturin-action@v1
        with:
          working-directory: rust/regipy-py
          command: sdist
          args: --out dist
      - uses: actions/upload-artifact@v4
        with: { name: sdist, path: rust/regipy-py/dist/*.tar.gz }

  publish:
    needs: [build-wheels, build-sdist]
    runs-on: ubuntu-latest
    permissions: { id-token: write }   # PyPI Trusted Publishing
    steps:
      - uses: actions/download-artifact@v4
        with: { path: dist, merge-multiple: true }
      - uses: pypa/gh-action-pypi-publish@release/v1
        with: { packages-dir: dist }
```

### `.github/workflows/test.yml` additions

```yaml
  test-with-rust-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - uses: dtolnay/rust-toolchain@stable
      - name: Install regipy with fast extra
        run: |
          python -m pip install -e ".[full,fast,dev]"
          (cd rust/regipy-py && maturin develop --release)
      - name: Run tests
        env: { REGIPY_BACKEND: rust }
        run: pytest regipy_tests/

  bench-regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          xzcat regipy_tests/data/SYSTEM.xz > /tmp/SYSTEM
          ./rust/target/release/walk values /tmp/SYSTEM 5
      # Compare against a baseline JSON committed in the repo, fail if
      # median_ms > baseline * 1.5
```

### Versioning

- `regipy-rs` versioned independently (semver).
- `regipy[fast]` extra pins a compatible range, e.g.
  `regipy-rs >= 0.1, < 0.2`.
- ABI: abi3-py38 means we never need to rebuild for new CPython releases.

## Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Wheel build fails on a target | sdist + Rust toolchain build path always works as fallback. |
| Behavior diverges from Python parser | Path-by-path test on every hive in `regipy_tests/data/` runs in CI for both backends. |
| Plugin authors reach into `RegistryHive` internals | Keep all public dataclass shapes identical; add a deprecation shim if anyone uses `_stream`. |
| Mmap on huge hives | mmap is fine for read-only; falls back to `Vec<u8>` for stdin/buffer input. |
| Windows MSVC link failures | `dtolnay/rust-toolchain` and `maturin-action` handle this; tested in cibuildwheel. |

## Effort estimate

| Phase | Effort | Notes |
|-------|-------:|-------|
| 1 — POC | done | ~1 night |
| 2 — feature parity | 3–5 days | VK type decoding is the bulk of it |
| 3 — backend swap | 2–3 days | shim + tests |
| 4 — transaction logs | 2 days | well-defined spec |
| 5 — CLI tools | 1 day | mostly thin wrappers |
| 6 — CI + release | 1–2 days | maturin-action + cibuildwheel are turnkey |

**Total: ~2 weeks of focused work** to ship a fully-backwards-compatible
release with opt-in Rust acceleration.
