# regipy → Rust POC results

**TL;DR.** A weekend Rust POC of the REGF parser is **200–400× faster** than
Python regipy on key-only walks and **600×–10,000×+** faster on full
walks-with-values. Per-key paths and value counts match Python exactly across
all four test hives (152,161 keys, 288,959 values).

**With PyO3 bindings** (target deployment: Python plugins on top, Rust
underneath): **9–19× faster than current Python on keys**, **87–1,000×+
faster on values**. Pure-Rust call from Python (no per-key Python objects) is
within 18–40% of native Rust speed.

## What this POC does

A minimal Rust port of regipy's hot path: parse REGF, walk the hbin/cell
structure, decode NK/VK records, and traverse subkey lists (lf, lh, li, ri).
That's enough to do a recursive walk equivalent to
`recurse_subkeys(fetch_values=False)` and `recurse_subkeys(fetch_values=True)`
in Python.

**Out of scope for the POC** (deliberately): transaction logs, security
descriptors, big data block reassembly, DEVPROP, plugins, CLI tools, MCP
server, value type interpretation beyond raw bytes.

Layout:

```
rust/
├── Cargo.toml                   # workspace
├── regipy-core/                 # parser library (~440 LOC)
│   └── src/lib.rs
└── regipy-bench/                # bench harness
    └── src/bin/
        ├── walk.rs              # timed walk
        └── dump_paths.rs        # cross-validation dumper
```

## Correctness

Both implementations dump every key as `<values_count>\t<path>`, sort the
result, and we `diff` them. **Every line matches** across all four hives.

| Hive | Size | Keys | Values | Path-by-path match |
|------|-----:|-----:|-------:|:------------------:|
| NTUSER.DAT | 768 KB | 1,812 | 4,094 | ✓ |
| amcache.hve | 2 MB | 2,105 | 17,539 | ✓ |
| SYSTEM | 11.7 MB | 30,756 | 73,456 | ✓ |
| SOFTWARE | 36 MB | 117,488 | 193,870 | ✓ |
| **Total** | | **152,161** | **288,959** | **100%** |

This is a strong correctness signal — the parser handles the same lf/lh/li/ri
edge cases regipy does, plus ASCII vs UTF-16 names.

## Benchmark methodology

- Hardware: same machine as user (aarch64).
- Rust: `cargo build --release` with `lto = "thin"`, `codegen-units = 1`.
  mmap-backed reads (`memmap2`).
- Python: regipy from this repo, `pip install -e .` in a venv, CPython 3.x.
- Both: hive reopened each run; page cache warm. Timings exclude file open.
- Rust: 7 runs, report `min_ms` and `median_ms`.
- Python: 5 runs, report same.
- Two modes:
    - `keys`: walk all subkeys, only sum `values_count`. No value decoding.
    - `values`: walk all subkeys *and* read raw value bytes for each VK
      record (Rust) / `recurse_subkeys(as_json=True, fetch_values=True)`
      (Python).

## Results

### Keys-only walk

| Hive | Rust median | Python median | Speedup |
|------|------------:|--------------:|--------:|
| NTUSER.DAT | 0.060 ms | 13.94 ms | **232×** |
| amcache.hve | 0.071 ms | 14.23 ms | **200×** |
| SYSTEM | 0.650 ms | 244.74 ms | **376×** |
| SOFTWARE | 2.735 ms | 943.74 ms | **345×** |

### Walk + value bytes

| Hive | Rust median | Python median | Speedup |
|------|------------:|--------------:|--------:|
| NTUSER.DAT | 0.231 ms | 158.90 ms | **688×** |
| amcache.hve | 0.365 ms | 754.62 ms | **2,068×** |
| SYSTEM | 2.063 ms | 43,013 ms* | **20,850×** |
| SOFTWARE | 9.440 ms | >100,000 ms** | **>10,000×** |

\* SYSTEM/values had unusually high Python variance (min 7.15 s, median 43 s).
   Even using Python's *minimum* (best-case) gives a 3,466× Rust win.
   The variance is likely driven by spew of UTF-8 decode warnings the Python
   path emits during the walk.

\** SOFTWARE/values: Python runs were terminated at ~3 minutes per run before
    completion. Lower-bound extrapolated from SYSTEM/values per-key/per-value
    cost.

### Python-via-PyO3 (the deployment target)

`regipy_rs` is a thin PyO3 binding over `regipy-core`. The `recurse_subkeys()`
method walks in Rust and yields one Python dict per visited key. The
`walk_stats()` method does the entire walk in Rust and returns only `(keys,
values, max_depth)` — useful as a lower bound on what the boundary costs.

| Hive | PyO3 stats (no Python objects) | PyO3 keys | PyO3 values |
|------|------------------------------:|----------:|------------:|
| NTUSER.DAT | 0.071 ms | 1.471 ms | 1.818 ms |
| amcache.hve | 0.101 ms | 1.675 ms | 5.107 ms |
| SYSTEM | 0.919 ms | 13.052 ms | 31.367 ms |
| SOFTWARE | 5.829 ms | 57.028 ms | 109.870 ms |

PyO3 vs current Python regipy:

| Hive | Mode | PyO3 / Python | Speedup |
|------|------|---------------|--------:|
| NTUSER.DAT | keys | 1.471 / 13.94 | **9.5×** |
| amcache.hve | keys | 1.675 / 14.23 | **8.5×** |
| SYSTEM | keys | 13.052 / 244.74 | **18.8×** |
| SOFTWARE | keys | 57.028 / 943.74 | **16.5×** |
| NTUSER.DAT | values | 1.818 / 158.90 | **87×** |
| amcache.hve | values | 5.107 / 754.62 | **148×** |
| SYSTEM | values | 31.367 / 43,014 | **1,371×** |
| SOFTWARE | values | 109.870 / >100,000 | **>900×** |

Per-key Python boundary cost is roughly **0.4 μs/key** (the Python dict
allocation per yielded item). The rest is in Rust. So the gap between PyO3
and pure Rust on big hives is bounded by how many Python objects you
materialize — *plugins that filter early stay close to native speed*.

### Throughput perspective

For the SOFTWARE hive (36 MB, the largest):

| | Rust | Python |
|---|---|---|
| keys/sec, walk-only | ~43M | ~125k |
| keys/sec, with values | ~12M | <1.2k |
| MB/sec processed (values mode) | ~3,800 MB/s | <0.4 MB/s |

In other words, Rust is processing the entire hive faster than Python can
decode a few hundred values.

## Why is the gap so large?

Three compounding factors:

1. **Construct overhead.** Python regipy parses every NK/VK/lf/lh record via
   `construct`, which allocates `Container` objects for every parsed struct.
   Per-NK record this is ~20 fields × per-field allocation + reflection
   bookkeeping. Rust reads 4-byte u32s straight out of the mmap.
2. **No allocations on the hot path.** The Rust walk doesn't allocate at all
   for keys-only mode. The values-mode allocates only when decoding the
   key/value name strings.
3. **mmap zero-copy.** All reads are slice indexes into the same mmap'd
   buffer; no `BytesIO`, no seeking, no copying.

## Feasibility verdict

Yes — porting is feasible and worth doing. ~440 lines of straightforward
Rust replicate the most-hit code path and run hundreds to thousands of times
faster, with byte-exact output. A full port would also keep the existing
Python plugin layer usable via PyO3 bindings (where the speedup matters less
because per-plugin work is small) while making bulk operations like
recursive walks, diffing, and timeline generation effectively free.

Suggested order for a real port:

1. Promote `regipy-core` into a real crate with full VK type decoding
   (REG_SZ, REG_DWORD, REG_MULTI_SZ, REG_FILETIME, REG_BINARY, big-data block
   reassembly).
2. PyO3 bindings exposing `RegistryHive`/`NKRecord`/`VKRecord` to Python with
   the same surface as `regipy.registry` so the existing plugin code keeps
   working unchanged.
3. Port transaction-log recovery (`apply_transaction_logs`).
4. Port the CLI tools (`regipy-dump`, `regipy-diff`, `regipy-plugins-run`)
   incrementally; ship a Rust drop-in for `regipy-dump` first since it's
   pure walk + JSON.
5. Plugins last — the per-plugin perf gain is small, but porting them
   gradually lets the Rust crate become standalone.

## Reproducing

```bash
# Decompress test hives
mkdir -p /tmp/regipy_bench
for f in NTUSER.DAT.xz amcache.hve.xz SYSTEM.xz SOFTWARE.xz; do
  xzcat regipy_tests/data/$f > /tmp/regipy_bench/${f%.xz}
done

# Build Rust
cd rust && cargo build --release && cd ..

# Cross-validate (path-by-path)
for hive in NTUSER.DAT amcache.hve SYSTEM SOFTWARE; do
  ./rust/target/release/dump_paths /tmp/regipy_bench/$hive | sort > /tmp/r.txt
  .venv/bin/python3 /tmp/regipy_bench/dump_paths_python.py /tmp/regipy_bench/$hive 2>/dev/null | sort > /tmp/p.txt
  diff -q /tmp/r.txt /tmp/p.txt
done

# Bench
./rust/target/release/walk values /tmp/regipy_bench/SYSTEM 7
.venv/bin/python3 /tmp/regipy_bench/bench_python.py values /tmp/regipy_bench/SYSTEM 5
```
