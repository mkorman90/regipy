# regipy-rs benchmarks

Pure-Python parser (`regipy.registry`) vs Rust backend (`regipy.registry_rs`),
best of 3 runs per scenario. Both backends produce identical output
(enforced by `regipy_tests/comparison_test.py`).

- Date: 2026-07-11
- Machine: Linux-6.19.14-108.fc42.x86_64-x86_64-with-glibc2.41 / Python 3.11.9
- Timing includes hive loading, traversal and value decoding, and for the
  Rust backend also the construction of the Python `Subkey`/`Value`
  dataclasses it returns (i.e. real end-to-end cost, not just parsing).

## NTUSER.DAT (0.8 MB)

| Scenario | Python | Rust | Speedup |
|----------|-------:|-----:|--------:|
| full traversal + values (as_json) | 173 ms | 5 ms | **38.4x** |
| full traversal, no values | 32 ms | 2 ms | **15.1x** |
| hive load + root | 0 ms | 0 ms | **2.5x** |

## SYSTEM (11.2 MB)

| Scenario | Python | Rust | Speedup |
|----------|-------:|-----:|--------:|
| full traversal + values (as_json) | 23,090 ms | 91 ms | **252.7x** |
| full traversal, no values | 733 ms | 45 ms | **16.5x** |
| hive load + root | 2 ms | 2 ms | **1.2x** |

## SOFTWARE (36.0 MB)

| Scenario | Python | Rust | Speedup |
|----------|-------:|-----:|--------:|
| full traversal + values (as_json) | 745,552 ms | 292 ms | **2550.2x** |
| full traversal, no values | 2,634 ms | 183 ms | **14.4x** |
| hive load + root | 16 ms | 16 ms | **1.0x** |

## UsrClass.dat (2.8 MB)

| Scenario | Python | Rust | Speedup |
|----------|-------:|-----:|--------:|
| full traversal + values (as_json) | 948 ms | 17 ms | **54.9x** |
| full traversal, no values | 148 ms | 9 ms | **16.7x** |
| hive load + root | 0 ms | 0 ms | **1.3x** |

## amcache.hve (2.0 MB)

| Scenario | Python | Rust | Speedup |
|----------|-------:|-----:|--------:|
| full traversal + values (as_json) | 837 ms | 12 ms | **67.5x** |
| full traversal, no values | 40 ms | 3 ms | **14.3x** |
| hive load + root | 0 ms | 0 ms | **1.2x** |

## SYSTEM_WIN_10_1709 (14.8 MB)

| Scenario | Python | Rust | Speedup |
|----------|-------:|-----:|--------:|
| full traversal + values (as_json) | 118,727 ms | 111 ms | **1067.8x** |
| full traversal, no values | 867 ms | 57 ms | **15.2x** |
| hive load + root | 3 ms | 3 ms | **1.0x** |

## Forensic parity evidence

SHA-256 over the canonicalized full traversal output — every key path,
timestamp, value name/type/content, serialized as sorted JSON, one line
per key. Both backends must produce the identical digest. Recompute with
`traversal_digest()` in `regipy-rs/benchmark.py`.

| Hive | Keys | Values | Traversal SHA-256 (both backends) | Identical |
|------|-----:|-------:|-----------------------------------|:---------:|
| NTUSER.DAT | 1,812 | 4,094 | `3b38eee434289759e8f0be6c671c49d155fe5871a4b94c7385bd97ce1e6ca182` | ✅ |
| SYSTEM | 30,756 | 73,456 | `cd87acaadd57dd619eb1d531a12cbe45092c4303950febb7902ecadf81ebf3d0` | ✅ |
| SOFTWARE | 117,488 | 193,870 | `a0f3cb5712a25651b04630699935bce62514ed8e75a7b44093c6b54171717771` | ✅ |
| UsrClass.dat | 6,205 | 12,369 | `3453eff9006261b0b51162b3a305bb58be6074be8207ae2bbd3127ba25f4f389` | ✅ |
| amcache.hve | 2,105 | 17,539 | `c2250ad20c29e63fdeb157c2812e1513400b125f0d87d7a5a6b124ddeba6f381` | ✅ |
| SYSTEM_WIN_10_1709 | 43,211 | 90,283 | `55e3dce277462305c63fa9c88d73d665c94bd1008171e57cb938a11d53b64caf` | ✅ |

Beyond these digests, `regipy_tests/comparison_test.py` enforces 1:1
parity over the full 17-hive test corpus: entry-by-entry traversal in
both `as_json` modes (order included), key navigation, security
descriptors (owner/group SIDs, DACL/SACL ACEs), partial hives, corrupted
hives (identical partial output and error behavior), end-to-end plugin
output for every validated plugin, and a 60,000+ sample FILETIME
conversion fuzz (bit-identical timestamps, including rounding and
overflow-clamp edge cases).

## Profiling: where the time goes

`cProfile` of a full `as_json` traversal of UsrClass.dat (6,205 keys),
top functions by cumulative time.

**Python backend** — dominated by per-record `construct` struct parsing
and value decoding:

```
         2540885 function calls (2450810 primitive calls) in 1.623 seconds
   Ordered by: cumulative time
   List reduced from 121 to 10 due to restriction <10>
   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        2    0.001    0.001    1.643    0.822 {built-in method builtins.sum}
     6206    0.004    0.000    1.642    0.000 benchmark.py:51(<genexpr>)
45543/6206    0.042    0.000    1.638    0.000 registry.py:164(recurse_subkeys)
     4396    0.011    0.000    1.274    0.000 registry.py:210(<listcomp>)
    16765    0.123    0.000    0.999    0.000 registry.py:481(iter_values)
    12369    0.046    0.000    0.531    0.000 registry.py:441(read_value)
   284770    0.490    0.000    0.490    0.000 {method 'read' of '_io.BytesIO' objects}
    43635    0.049    0.000    0.443    0.000 core.py:290(parse_stream)
44555/43635    0.019    0.000    0.364    0.000 core.py:311(_parsereport)
    21625    0.009    0.000    0.300    0.000 core.py:786(_parse)
```

**Rust backend** — parsing/decoding moved to native code; the remaining
Python time is `Subkey` dataclass construction in the wrapper:

```
         24835 function calls in 0.024 seconds
   Ordered by: cumulative time
   List reduced from 14 to 10 due to restriction <10>
   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        1    0.001    0.001    0.023    0.023 {built-in method builtins.sum}
     6206    0.002    0.000    0.023    0.000 benchmark.py:51(<genexpr>)
     6206    0.017    0.000    0.021    0.000 registry_rs.py:202(recurse_subkeys)
     6205    0.003    0.000    0.003    0.000 registry_rs.py:234(<listcomp>)
     6205    0.001    0.000    0.001    0.000 <string>:2(__init__)
        1    0.000    0.000    0.000    0.000 registry_rs.py:166(__init__)
        1    0.000    0.000    0.000    0.000 {method 'recurse' of 'regipy_rs.RegistryHive' objects}
        1    0.000    0.000    0.000    0.000 utils.py:156(identify_hive_type)
        1    0.000    0.000    0.000    0.000 {method 'root' of 'regipy_rs.RegistryHive' objects}
        4    0.000    0.000    0.000    0.000 {method 'endswith' of 'str' objects}
```

Two wrapper hot spots were eliminated during development, measured on this
hive: `dataclasses.asdict()` per value (~78% of the Rust backend's runtime
before it was replaced with direct dict construction) and per-key
`convert_wintime()` (FILETIME conversion now happens in Rust with
arithmetic verified bit-identical by the fuzz test).

## Known divergences (disclaimer)

The Rust backend is output-identical to the Python parser for every key path,
timestamp, value name, value type and value content across the entire test
corpus (see above). The intentional differences are:

- **Exception types on corrupted hives.** The Rust backend always raises
  `RegistryParsingException`. The Python parser raises the same exception on
  most corruption, but some paths leak raw `construct` errors (e.g.
  `StreamError` for a truncated `REG_DWORD`). Where both raise, offsets and
  messages may be worded differently; the partially yielded entries before the
  error are identical.
- **Cyclic subkey lists.** A maliciously corrupted hive whose subkey lists form
  a cycle makes the Python parser fail with `RecursionError` (interpreter
  recursion limit). The Rust backend raises `RegistryParsingException` after a
  depth of 1000 instead of looping.
- **Object identity, not type identity.** `RegistryHive`/`NKRecord`/`header`
  are different classes that are attribute-compatible (including
  `dict(key.header)` and header equality); `isinstance` checks against
  `regipy.registry.NKRecord` and `repr()` output differ. `Value`/`Subkey`
  results are the exact same dataclasses.
- **Not implemented on the Rust backend:** the internal `RegistryHive._stream`
  attribute and `get_hbin_at_offset()` (used by the CLI header checksum path
  and transaction-log recovery, which remain pure-Python by design).
- **Corrupt size fields.** On-disk counts/sizes are untrusted: the Rust backend
  caps pre-allocations where the Python parser would attempt (and typically
  fail) huge allocations. This has no effect on output for parseable hives.

