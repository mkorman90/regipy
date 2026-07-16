# regipy-rs

Rust-accelerated core parser for [regipy](https://github.com/mkorman90/regipy),
the OS-independent Python library for parsing offline Windows registry hives
(REGF format).

> **Status: alpha.** The Rust backend is validated 1:1 against the pure-Python
> parser over regipy's full test-hive corpus (every key, every value), but the
> API and packaging may still change.

## What it is

`regipy_rs` is a PyO3 native extension implementing the performance-critical
parts of registry parsing: hive loading, key navigation, recursive traversal
and value decoding. It is not meant to be used directly — install it alongside
regipy and use the drop-in wrapper:

```bash
pip install regipy[rust]
```

```python
from regipy.registry_rs import RegistryHive  # instead of regipy.registry

reg = RegistryHive("/path/to/NTUSER.DAT")
key = reg.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Run")
for value in key.iter_values(as_json=True):
    print(value.name, value.value)

for entry in reg.recurse_subkeys(as_json=True):
    ...
```

The wrapper exposes the exact same API and dataclasses as
`regipy.registry.RegistryHive`, so existing code and all regipy plugins work
unchanged.

## Parity guarantees

Output semantics intentionally match the Python parser, including its quirks
(string trimming behavior, decode order of `try_decode_binary`, generator
error semantics on corrupted hives). Parity is enforced by
`regipy_tests/comparison_test.py`, which traverses every test hive with both
backends and compares every key path, timestamp, value name, type and content.

## Building from source

```bash
pip install maturin
cd regipy-rs
maturin build --release
pip install target/wheels/regipy_rs-*.whl
```

## Benchmarks

`BENCHMARKS.md` contains the full report: per-hive timings, `cProfile`
breakdowns of both backends, SHA-256 parity digests over the complete
traversal output, and a disclaimer documenting intentional divergences.
The entire report is regenerated from source by:

```bash
python regipy-rs/benchmark.py --runs 3
```

See the *Reproducing this report* section of `BENCHMARKS.md` for
prerequisites and caveats.
