"""1:1 backend parity harness — DFIR safety gate.

Walks every key and every value of each test hive twice (Python construct
backend vs Rust backend) and compares **byte-exact**. Any divergence aborts
with full context (path, value name, type, both sides shown).

This is the forensic correctness contract: regipy MUST NOT silently drop or
mutate values when switching backends. If a single (path, value_name,
value_type, value, last_modified) tuple diverges, this script fails — and
the CI job blocks the merge.

Usage:
    PYTHONPATH=. python regipy_tests/parity/parity_check.py            # default tier
    PYTHONPATH=. python regipy_tests/parity/parity_check.py --deep      # adds SOFTWARE/SYSTEM
    PYTHONPATH=. python regipy_tests/parity/parity_check.py --hive NTUSER.DAT
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from tempfile import mktemp
from typing import Iterable, Iterator, Optional

# Default tier — small + medium hives. Runs quickly enough for every PR.
DEFAULT_HIVES = [
    "NTUSER.DAT.xz",
    "amcache.hve.xz",
    "NTUSER_BAGMRU.DAT.xz",
    "UsrClass.dat.xz",
    "ntuser_software_partial.xz",
    "SYSTEM_2.xz",
    "NTUSER_with_winscp.DAT.xz",
]

# Deep tier — adds the big hives. Run on release tags or via --deep.
DEEP_HIVES = DEFAULT_HIVES + [
    "SOFTWARE.xz",
    "SYSTEM.xz",
]

# Hives that must be loaded with explicit hive_type/partial_hive_path.
HIVE_OPTIONS = {
    "ntuser_software_partial.xz": dict(hive_type="ntuser", partial_hive_path=r"\Software"),
}

DATA_DIR = Path(__file__).parent.parent.joinpath("data")


def _decompress(name: str) -> str:
    import lzma

    src = DATA_DIR.joinpath(name)
    dst = mktemp(prefix="parity_", suffix=f"_{name}")
    with open(dst, "wb") as out, lzma.open(src) as f:
        out.write(f.read())
    return dst


@contextmanager
def _backend(name: str):
    """Switch the backend by env var, then re-import regipy.

    Uses the env var because that's the public API. Re-imports clear cached
    state so the patch installs (or doesn't) cleanly each time.
    """
    prior = os.environ.get("REGIPY_BACKEND")
    os.environ["REGIPY_BACKEND"] = name
    # Drop cached regipy modules so __init__.maybe_install runs fresh
    for mod in [m for m in list(sys.modules) if m == "regipy" or m.startswith("regipy.")]:
        del sys.modules[mod]
    importlib.invalidate_caches()
    try:
        yield
    finally:
        if prior is None:
            del os.environ["REGIPY_BACKEND"]
        else:
            os.environ["REGIPY_BACKEND"] = prior
        for mod in [m for m in list(sys.modules) if m == "regipy" or m.startswith("regipy.")]:
            del sys.modules[mod]
        importlib.invalidate_caches()


def _walk_hive(hive_path: str, hive_options: dict) -> list[dict]:
    """Walk every key + value, return a normalized list of records."""
    # Defer import until inside _backend context
    from regipy.registry import RegistryHive

    hive = RegistryHive(hive_path, **hive_options)
    out: list[dict] = []
    for sk in hive.recurse_subkeys(as_json=True, fetch_values=True):
        # sk.values is list of dicts (because as_json=True)
        norm_values = []
        for v in sk.values or []:
            # Normalize: bytes → hex string for stable comparison
            val = v["value"]
            if isinstance(val, (bytes, bytearray)):
                val = ("hex:" + val.hex())
            elif isinstance(val, list):
                val = list(val)
            norm_values.append({
                "name": v["name"],
                "value_type": v["value_type"],
                "value": val,
                "is_corrupted": v.get("is_corrupted", False),
            })
        ts = sk.timestamp
        if hasattr(ts, "isoformat"):
            ts = ts.isoformat()
        out.append({
            "path": sk.path,
            "subkey_name": sk.subkey_name,
            "timestamp": ts,
            "values_count": sk.values_count,
            "values": norm_values,
            "actual_path": sk.actual_path,
        })
    # Sort for stable comparison (recurse order may differ slightly between
    # backends in edge cases; we care about set equality, not order).
    out.sort(key=lambda r: (r["path"], r["subkey_name"]))
    for rec in out:
        rec["values"].sort(key=lambda v: (v["name"], v["value_type"]))
    return out


def _diff_record(py_rec: dict, rust_rec: dict) -> list[str]:
    diffs: list[str] = []
    for k in ("path", "subkey_name", "timestamp", "values_count"):
        if py_rec.get(k) != rust_rec.get(k):
            diffs.append(
                f"  field={k!r} python={py_rec.get(k)!r} rust={rust_rec.get(k)!r}"
            )
    py_vals = {(v["name"], v["value_type"]): v for v in py_rec["values"]}
    rust_vals = {(v["name"], v["value_type"]): v for v in rust_rec["values"]}
    only_py = set(py_vals) - set(rust_vals)
    only_rust = set(rust_vals) - set(py_vals)
    for k in sorted(only_py):
        diffs.append(f"  value-only-in-python {k}: {py_vals[k]!r}")
    for k in sorted(only_rust):
        diffs.append(f"  value-only-in-rust   {k}: {rust_vals[k]!r}")
    for k in sorted(set(py_vals) & set(rust_vals)):
        pv, rv = py_vals[k], rust_vals[k]
        if pv != rv:
            diffs.append(
                f"  value-mismatch {k}\n"
                f"    python: {pv!r}\n"
                f"    rust:   {rv!r}"
            )
    return diffs


def compare_hive(name: str) -> tuple[int, int, list[str]]:
    """Walk one hive twice and compare. Returns (key_count, divergence_count, diffs)."""
    print(f"  [.] decompressing {name}", flush=True)
    hive_path = _decompress(name)
    options = HIVE_OPTIONS.get(name, {})
    try:
        print(f"  [.] walk via Python backend", flush=True)
        t0 = time.perf_counter()
        with _backend("python"):
            py_records = _walk_hive(hive_path, options)
        py_dt = time.perf_counter() - t0

        print(f"  [.] walk via Rust backend", flush=True)
        t0 = time.perf_counter()
        with _backend("rust"):
            rust_records = _walk_hive(hive_path, options)
        rust_dt = time.perf_counter() - t0

        py_index = {(r["path"], r["subkey_name"]): r for r in py_records}
        rust_index = {(r["path"], r["subkey_name"]): r for r in rust_records}

        diffs: list[str] = []
        only_py = set(py_index) - set(rust_index)
        only_rust = set(rust_index) - set(py_index)
        for k in sorted(only_py)[:20]:
            diffs.append(f"  KEY-ONLY-IN-PYTHON {k}")
        for k in sorted(only_rust)[:20]:
            diffs.append(f"  KEY-ONLY-IN-RUST   {k}")
        if only_py or only_rust:
            diffs.append(
                f"  (total only-in-python={len(only_py)} only-in-rust={len(only_rust)})"
            )

        for k in sorted(set(py_index) & set(rust_index)):
            d = _diff_record(py_index[k], rust_index[k])
            if d:
                diffs.append(f"DIVERGENCE at key {k}:")
                diffs.extend(d)

        py_value_count = sum(len(r["values"]) for r in py_records)
        speedup = py_dt / rust_dt if rust_dt > 0 else 0
        print(
            f"  [=] {name}: keys={len(py_records)} values={py_value_count} "
            f"py={py_dt:.2f}s rust={rust_dt:.2f}s speedup={speedup:.1f}x",
            flush=True,
        )
        return len(py_records), len(diffs), diffs
    finally:
        try:
            os.remove(hive_path)
        except OSError:
            pass


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--deep", action="store_true", help="Also run on SYSTEM and SOFTWARE")
    parser.add_argument("--hive", action="append", help="Run on a specific hive only (can repeat)")
    parser.add_argument("--manifest", help="Write a JSON manifest of the walk to this path")
    args = parser.parse_args(argv)

    if args.hive:
        hives = args.hive
    elif args.deep:
        hives = DEEP_HIVES
    else:
        hives = DEFAULT_HIVES

    # Ensure regipy_rs is importable; if not, this run is meaningless.
    try:
        import regipy_rs  # noqa: F401
    except ImportError:
        print("ERROR: regipy_rs is not installed; parity check requires it.", file=sys.stderr)
        return 2

    print(f"[*] Parity check across {len(hives)} hive(s)")
    failed = 0
    total_keys = 0
    total_diffs = 0

    for name in hives:
        try:
            keys, ndiff, diffs = compare_hive(name)
        except FileNotFoundError as e:
            print(f"  [!] {name}: missing — {e}", flush=True)
            continue
        total_keys += keys
        total_diffs += ndiff
        if ndiff:
            failed += 1
            print(f"  [X] {name}: {ndiff} divergence(s)", flush=True)
            for d in diffs[:50]:
                print(d, flush=True)
            if len(diffs) > 50:
                print(f"  ... ({len(diffs) - 50} more diffs suppressed)", flush=True)

    print()
    print(f"[*] Summary: {len(hives)} hives, {total_keys} keys total, {total_diffs} divergences")

    if args.manifest:
        # Write a JSON summary that can be archived from CI
        with open(args.manifest, "w") as f:
            json.dump({
                "hives": hives,
                "total_keys": total_keys,
                "total_divergences": total_diffs,
                "failed_hives": failed,
            }, f, indent=2)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
