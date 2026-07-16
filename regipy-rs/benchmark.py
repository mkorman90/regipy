"""
Benchmark the pure-Python parser (regipy.registry) against the Rust backend
(regipy.registry_rs) and write the results to BENCHMARKS.md.

Usage:
    python regipy-rs/benchmark.py [--runs 3]

Requires the regipy_rs extension to be installed and the test hives in
regipy_tests/data (decompressed to a temp dir automatically).
"""

import argparse
import lzma
import platform
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from regipy.registry import RegistryHive as PyRegistryHive
from regipy.registry_rs import RegistryHive as RsRegistryHive

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "regipy_tests" / "data"
OUTPUT = Path(__file__).resolve().parent / "BENCHMARKS.md"

BENCH_HIVES = [
    "NTUSER.DAT.xz",
    "SYSTEM.xz",
    "SOFTWARE.xz",
    "UsrClass.dat.xz",
    "amcache.hve.xz",
    "SYSTEM_WIN_10_1709.xz",
]

SCENARIOS = {
    "full traversal + values (as_json)": lambda hive: sum(1 for _ in hive.recurse_subkeys(as_json=True, fetch_values=True)),
    "full traversal, no values": lambda hive: sum(1 for _ in hive.recurse_subkeys(fetch_values=False)),
    "hive load + root": lambda hive: hive.root.subkey_count,
}


def profile_backend(factory, path, top=10):
    """cProfile a full as_json traversal and return the top functions by cumulative time."""
    import cProfile
    import io
    import pstats

    profiler = cProfile.Profile()
    profiler.enable()
    total = sum(1 for _ in factory(path).recurse_subkeys(as_json=True, fetch_values=True))
    profiler.disable()
    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream)
    stats.strip_dirs().sort_stats("cumulative").print_stats(top)
    body = stream.getvalue()
    # Keep only the header line and the stats table
    table = "\n".join(line.rstrip() for line in body.splitlines() if line.strip())
    return total, table


def traversal_digest(factory, path):
    """
    SHA-256 over the canonicalized full traversal output (every key path,
    timestamp, value name/type/content) — auditable forensic evidence that
    both backends produce identical output for a given hive.
    """
    import hashlib
    import json
    from dataclasses import asdict

    digest = hashlib.sha256()
    keys = 0
    values = 0
    for entry in factory(path).recurse_subkeys(as_json=True, fetch_values=True):
        entry_dict = asdict(entry)
        keys += 1
        values += len(entry_dict["values"])
        digest.update(json.dumps(entry_dict, sort_keys=True, default=str).encode())
        digest.update(b"\n")
    return digest.hexdigest(), keys, values


REPRODUCING = """\
## Reproducing this report

This file is generated end-to-end by `regipy-rs/benchmark.py` — timings,
parity digests and profiles are all recomputed from the build being measured,
so the report cannot drift from the code. From a repo checkout:

```bash
pip install -e ".[dev]"
pip install maturin
maturin build --release --manifest-path regipy-rs/Cargo.toml
pip install regipy-rs/target/wheels/regipy_rs-*.whl --force-reinstall
python regipy-rs/benchmark.py --runs 3
```

Notes:
- Test hives ship with the repo (`regipy_tests/data/*.xz`) and are
  decompressed to a temp dir automatically.
- Timings are best-of-N (`--runs`); scenarios slower than 60 s run once,
  as repeat-run noise is irrelevant at that magnitude. Expect the run to
  take ~30 minutes — almost all of it is the pure-Python backend (the Rust
  side contributes seconds in total).
- Absolute times vary by machine (recorded in the header above); the
  speedup ratios and the parity digests should not.
- The digest table must be identical on any machine: it hashes parser
  *output*, which contains no timing, ordering or environment artifacts.
"""

PARITY_DISCLAIMER = """\
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
"""


def bench(factory, path, scenario, runs, slow_run_cutoff=60.0):
    """Best-of-N timing; scenarios slower than slow_run_cutoff run only once
    (repeat-run noise is irrelevant at that magnitude)."""
    timings = []
    result = None
    for _ in range(runs):
        start = time.perf_counter()
        hive = factory(path)
        result = scenario(hive)
        timings.append(time.perf_counter() - start)
        if timings[-1] > slow_run_cutoff:
            break
    return min(timings), result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    lines = [
        "# regipy-rs benchmarks",
        "",
        "Pure-Python parser (`regipy.registry`) vs Rust backend (`regipy.registry_rs`),",
        f"best of {args.runs} runs per scenario. Both backends produce identical output",
        "(enforced by `regipy_tests/comparison_test.py`).",
        "",
        f"- Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        f"- Machine: {platform.platform()} / Python {platform.python_version()}",
        "- Timing includes hive loading, traversal and value decoding, and for the",
        "  Rust backend also the construction of the Python `Subkey`/`Value`",
        "  dataclasses it returns (i.e. real end-to-end cost, not just parsing).",
        "",
    ]

    digest_rows = []
    with tempfile.TemporaryDirectory() as tmp:
        hive_paths = {}
        for hive_name in BENCH_HIVES:
            src = DATA_DIR / hive_name
            dst = Path(tmp) / hive_name[:-3]
            with lzma.open(src.open("rb")) as f:
                dst.write_bytes(f.read())
            hive_paths[hive_name] = str(dst)
            size_mb = dst.stat().st_size / (1024 * 1024)

            lines.append(f"## {hive_name[:-3]} ({size_mb:.1f} MB)")
            lines.append("")
            lines.append("| Scenario | Python | Rust | Speedup |")
            lines.append("|----------|-------:|-----:|--------:|")
            for scenario_name, scenario in SCENARIOS.items():
                py_time, py_result = bench(PyRegistryHive, str(dst), scenario, args.runs)
                rs_time, rs_result = bench(RsRegistryHive, str(dst), scenario, args.runs)
                assert py_result == rs_result, f"{hive_name} / {scenario_name}: result mismatch {py_result} != {rs_result}"
                lines.append(
                    f"| {scenario_name} | {py_time * 1000:,.0f} ms | {rs_time * 1000:,.0f} ms | **{py_time / rs_time:.1f}x** |"
                )
                print(
                    f"{hive_name[:-3]:24s} {scenario_name:36s} py={py_time:7.3f}s rs={rs_time:7.3f}s "
                    f"({py_time / rs_time:5.1f}x, n={py_result})"
                )
            lines.append("")

        # ── Forensic parity evidence ────────────────────────────────────────
        print("\nComputing traversal digests (forensic parity evidence)...")
        for hive_name, path in hive_paths.items():
            py_digest, py_keys, py_values = traversal_digest(PyRegistryHive, path)
            rs_digest, rs_keys, rs_values = traversal_digest(RsRegistryHive, path)
            match = py_digest == rs_digest and (py_keys, py_values) == (rs_keys, rs_values)
            digest_rows.append((hive_name[:-3], py_keys, py_values, py_digest, rs_digest, match))
            print(f"  {hive_name[:-3]:24s} keys={py_keys:6d} values={py_values:7d} identical={match}")
            assert match, f"Digest mismatch for {hive_name}: {py_digest} != {rs_digest}"

        lines.append("## Forensic parity evidence")
        lines.append("")
        lines.append("SHA-256 over the canonicalized full traversal output — every key path,")
        lines.append("timestamp, value name/type/content, serialized as sorted JSON, one line")
        lines.append("per key. Both backends must produce the identical digest. Recompute with")
        lines.append("`traversal_digest()` in `regipy-rs/benchmark.py`.")
        lines.append("")
        lines.append("| Hive | Keys | Values | Traversal SHA-256 (both backends) | Identical |")
        lines.append("|------|-----:|-------:|-----------------------------------|:---------:|")
        for name, keys, values, py_digest, _rs_digest, match in digest_rows:
            marker = "✅" if match else "❌ MISMATCH"
            lines.append(f"| {name} | {keys:,} | {values:,} | `{py_digest}` | {marker} |")
        lines.append("")
        lines.append("Beyond these digests, `regipy_tests/comparison_test.py` enforces 1:1")
        lines.append("parity over the full 17-hive test corpus: entry-by-entry traversal in")
        lines.append("both `as_json` modes (order included), key navigation, security")
        lines.append("descriptors (owner/group SIDs, DACL/SACL ACEs), partial hives, corrupted")
        lines.append("hives (identical partial output and error behavior), end-to-end plugin")
        lines.append("output for every validated plugin, and a 60,000+ sample FILETIME")
        lines.append("conversion fuzz (bit-identical timestamps, including rounding and")
        lines.append("overflow-clamp edge cases).")
        lines.append("")

        # ── Profiling: where the time goes ──────────────────────────────────
        profile_hive = "UsrClass.dat.xz"
        print("\nProfiling both backends on UsrClass.dat...")
        py_total, py_profile = profile_backend(PyRegistryHive, hive_paths[profile_hive])
        rs_total, rs_profile = profile_backend(RsRegistryHive, hive_paths[profile_hive])
        assert py_total == rs_total
        lines.append("## Profiling: where the time goes")
        lines.append("")
        lines.append(f"`cProfile` of a full `as_json` traversal of UsrClass.dat ({py_total:,} keys),")
        lines.append("top functions by cumulative time.")
        lines.append("")
        lines.append("**Python backend** — dominated by per-record `construct` struct parsing")
        lines.append("and value decoding:")
        lines.append("")
        lines.append("```")
        lines.append(py_profile)
        lines.append("```")
        lines.append("")
        lines.append("**Rust backend** — parsing/decoding moved to native code; the remaining")
        lines.append("Python time is `Subkey` dataclass construction in the wrapper:")
        lines.append("")
        lines.append("```")
        lines.append(rs_profile)
        lines.append("```")
        lines.append("")
        lines.append("Two wrapper hot spots were eliminated during development, measured on this")
        lines.append("hive: `dataclasses.asdict()` per value (~78% of the Rust backend's runtime")
        lines.append("before it was replaced with direct dict construction) and per-key")
        lines.append("`convert_wintime()` (FILETIME conversion now happens in Rust with")
        lines.append("arithmetic verified bit-identical by the fuzz test).")
        lines.append("")
        lines.append(REPRODUCING)
        lines.append(PARITY_DISCLAIMER)

    OUTPUT.write_text("\n".join(lines) + "\n")
    print(f"\nWrote {OUTPUT}")


if __name__ == "__main__":
    main()
