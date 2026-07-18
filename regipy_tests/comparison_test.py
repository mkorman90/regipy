"""
1:1 comparison between the pure-Python parser (regipy.registry) and the
Rust-backed parser (regipy.registry_rs).

These tests are the parity contract for the Rust port: both backends must
produce identical output for every key path, timestamp, value name, value type
and value content, over every REGF test hive in regipy_tests/data — and
identical plugin results end-to-end.

Skipped automatically when the regipy_rs native extension is not installed.
"""

import lzma
import tempfile
from pathlib import Path

import pytest

from regipy.exceptions import RegistryParsingException
from regipy.registry import RegistryHive as PyRegistryHive

try:
    import regipy_rs  # noqa: F401

    from regipy.registry_rs import RegistryHive as RsRegistryHive

    HAS_RUST = True
except ImportError:
    HAS_RUST = False

pytestmark = pytest.mark.skipif(not HAS_RUST, reason="regipy_rs is not installed")

TEST_DATA_DIR = Path(__file__).parent / "data"

# Every REGF hive in the corpus. Transaction logs (.LOG1/.LOG2) are not
# standalone REGF files and are excluded.
HIVES = sorted(xz.name for xz in TEST_DATA_DIR.glob("*.xz") if ".log" not in xz.name.lower())

REGF_HEADER_FIELDS = [
    "primary_sequence_num",
    "secondary_sequence_num",
    "last_modification_time",
    "major_version",
    "minor_version",
    "file_type",
    "file_format",
    "root_key_offset",
    "hive_bins_data_size",
    "clustering_factor",
    "file_name",
    "checksum",
]


@pytest.fixture(scope="module")
def hive_paths():
    """Decompress each test hive once for the whole module."""
    paths = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name in HIVES:
            dst = Path(tmp) / name[: -len(".xz")]
            with lzma.open((TEST_DATA_DIR / name).open("rb")) as f:
                dst.write_bytes(f.read())
            paths[name] = str(dst)
        yield paths


def _load_both(hive_paths, hive_name):
    path = hive_paths[hive_name]
    return PyRegistryHive(path), RsRegistryHive(path)


@pytest.mark.parametrize("hive_name", HIVES)
def test_header_parity(hive_paths, hive_name):
    py_hive, rs_hive = _load_both(hive_paths, hive_name)
    for field in REGF_HEADER_FIELDS:
        assert getattr(py_hive.header, field) == getattr(rs_hive.header, field), field
    assert py_hive.name == rs_hive.name
    assert py_hive.hive_type == rs_hive.hive_type


@pytest.mark.parametrize("hive_name", HIVES)
def test_root_key_parity(hive_paths, hive_name):
    py_hive, rs_hive = _load_both(hive_paths, hive_name)
    py_root, rs_root = py_hive.root, rs_hive.root
    assert py_root.name == rs_root.name
    assert py_root.subkey_count == rs_root.subkey_count
    assert py_root.values_count == rs_root.values_count
    assert py_root.volatile_subkeys_count == rs_root.volatile_subkeys_count
    assert dict(py_root.header)["last_modified"] == rs_root.header.last_modified
    # dict(header) must be equivalent for every CM_KEY_NODE field
    py_header = dict(py_root.header)
    rs_header = dict(rs_root.header)
    py_header["flags"] = {k: v for k, v in dict(py_header["flags"]).items() if not k.startswith("_")}
    rs_header["flags"] = dict(rs_header["flags"])
    assert py_header == rs_header


def _collect_recursed(hive, **kwargs):
    """Traverse a hive, capturing entries and a trailing parse error if any."""
    entries = []
    error = None
    try:
        for entry in hive.recurse_subkeys(**kwargs):
            entries.append(entry)
    except RegistryParsingException as ex:
        error = type(ex).__name__
    return entries, error


@pytest.mark.parametrize("hive_name", HIVES)
@pytest.mark.parametrize("as_json", [True, False], ids=["as_json", "raw"])
def test_full_traversal_parity(hive_paths, hive_name, as_json):
    """
    The core parity test: full recursive traversal with values, compared
    entry-by-entry (order included) between backends.
    """
    py_hive, rs_hive = _load_both(hive_paths, hive_name)
    py_entries, py_error = _collect_recursed(py_hive, as_json=as_json, fetch_values=True)
    rs_entries, rs_error = _collect_recursed(rs_hive, as_json=as_json, fetch_values=True)

    assert py_error == rs_error, f"Traversal error mismatch: {py_error} != {rs_error}"
    assert len(py_entries) == len(rs_entries), f"Entry count mismatch: {len(py_entries)} != {len(rs_entries)}"

    for i, (py_entry, rs_entry) in enumerate(zip(py_entries, rs_entries)):
        assert py_entry.subkey_name == rs_entry.subkey_name, f"entry {i}: name"
        assert py_entry.path == rs_entry.path, f"entry {i}: path"
        assert py_entry.timestamp == rs_entry.timestamp, f"entry {i} ({py_entry.path}): timestamp"
        assert py_entry.values_count == rs_entry.values_count, f"entry {i} ({py_entry.path}): values_count"
        assert py_entry.actual_path == rs_entry.actual_path, f"entry {i} ({py_entry.path}): actual_path"
        assert py_entry.values == rs_entry.values, f"entry {i} ({py_entry.path}): values"


@pytest.mark.parametrize("hive_name", HIVES)
def test_traversal_without_values_parity(hive_paths, hive_name):
    py_hive, rs_hive = _load_both(hive_paths, hive_name)
    py_entries, py_error = _collect_recursed(py_hive, fetch_values=False)
    rs_entries, rs_error = _collect_recursed(rs_hive, fetch_values=False)
    assert py_error == rs_error
    assert [(e.subkey_name, e.path, e.timestamp, e.values_count) for e in py_entries] == [
        (e.subkey_name, e.path, e.timestamp, e.values_count) for e in rs_entries
    ]


def _sample_paths(hive, step, limit):
    """Sample key paths, tolerating traversal errors on corrupted hives."""
    entries, _ = _collect_recursed(hive, fetch_values=False)
    return [e.path for e in entries][::step][:limit]


@pytest.mark.parametrize("hive_name", HIVES)
def test_key_navigation_parity(hive_paths, hive_name):
    """get_key/get_subkey/get_value/class name parity over a sample of deep paths."""
    py_hive, rs_hive = _load_both(hive_paths, hive_name)

    # Sample every 17th key path from the traversal to keep runtime sane
    paths = _sample_paths(py_hive, 17, 200)
    for path in paths:
        py_key = py_hive.get_key(path)
        rs_key = rs_hive.get_key(path)
        assert py_key.name == rs_key.name, path
        assert py_key.subkey_count == rs_key.subkey_count, path
        assert py_key.values_count == rs_key.values_count, path
        assert py_key.header.last_modified == rs_key.header.last_modified, path
        assert [sk.name for sk in py_key.iter_subkeys()] == [sk.name for sk in rs_key.iter_subkeys()], path
        for trim_values in (True, False):
            py_values = py_key.get_values(as_json=False, trim_values=trim_values)
            rs_values = rs_key.get_values(as_json=False, trim_values=trim_values)
            assert py_values == rs_values, f"{path} (trim_values={trim_values})"
        if py_key.header.class_name_size:
            assert py_key.get_class_name() == rs_key.get_class_name(), path


@pytest.mark.parametrize("hive_name", HIVES)
def test_missing_key_parity(hive_paths, hive_name):
    from regipy.exceptions import RegistryKeyNotFoundException

    py_hive, rs_hive = _load_both(hive_paths, hive_name)
    for path in (r"\Nonexistent\Key\Path", r"\Nonexistent"):
        with pytest.raises(RegistryKeyNotFoundException):
            py_hive.get_key(path)
        with pytest.raises(RegistryKeyNotFoundException):
            rs_hive.get_key(path)


@pytest.mark.parametrize("hive_name", ["SYSTEM.xz", "NTUSER.DAT.xz", "SOFTWARE.xz", "SAM.xz"])
def test_security_info_parity(hive_paths, hive_name):
    py_hive, rs_hive = _load_both(hive_paths, hive_name)
    paths = _sample_paths(py_hive, 29, 100)
    for path in paths:
        py_key = py_hive.get_key(path)
        rs_key = rs_hive.get_key(path)
        try:
            py_sec = py_key.get_security_key_info()
        except Exception:
            continue  # Python parser failed on this SK record; skip
        rs_sec = rs_key.get_security_key_info()
        assert py_sec == rs_sec, path


@pytest.mark.parametrize(
    "hive_name",
    ["NTUSER.DAT.xz", "SYSTEM.xz", "SOFTWARE.xz", "SAM.xz", "UsrClass.dat.xz", "amcache.hve.xz", "SECURITY.xz"],
)
def test_plugin_output_parity(hive_paths, hive_name):
    """Run every relevant plugin against both backends and compare results."""
    from regipy.plugins.utils import run_relevant_plugins

    py_hive, rs_hive = _load_both(hive_paths, hive_name)
    py_results = run_relevant_plugins(py_hive, as_json=True)
    rs_results = run_relevant_plugins(rs_hive, as_json=True)
    assert sorted(py_results) == sorted(rs_results), "Different plugin sets ran"
    for plugin_name, py_result in py_results.items():
        assert py_result == rs_results[plugin_name], f"Plugin output mismatch: {plugin_name}"


def test_partial_hive_parity(hive_paths):
    from regipy.hive_types import NTUSER_HIVE_TYPE

    path = hive_paths["ntuser_software_partial.xz"]
    py_hive = PyRegistryHive(path, hive_type=NTUSER_HIVE_TYPE, partial_hive_path=r"\Software")
    rs_hive = RsRegistryHive(path, hive_type=NTUSER_HIVE_TYPE, partial_hive_path=r"\Software")

    py_key = py_hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Run")
    rs_key = rs_hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Run")
    assert py_key.name == rs_key.name
    assert py_key.get_values(as_json=True) == rs_key.get_values(as_json=True)

    py_entries, _ = _collect_recursed(py_hive, as_json=True)
    rs_entries, _ = _collect_recursed(rs_hive, as_json=True)
    assert [e.actual_path for e in py_entries] == [e.actual_path for e in rs_entries]


def test_convert_wintime_parity_fuzz():
    """
    The Rust backend converts FILETIME timestamps natively; its arithmetic must
    match regipy.utils.convert_wintime bit-for-bit, including the wintime/10
    float division, timedelta's round-half-even microsecond rounding, and the
    OverflowError -> 1601-01-01 epoch clamp.
    """
    import random

    from regipy.utils import convert_wintime

    rnd = random.Random(0x1E6F)
    samples = [0, 1, 5, 15, 25, 10_000_000, 2**63, 2**64 - 1]
    # Boundary around datetime.max (9999-12-31 23:59:59.999999)
    max_wintime = 2_650_467_743_999_999_990
    samples += [max_wintime + d for d in range(-20, 21)]
    # Realistic modern timestamps and broad random sweeps
    samples += [rnd.randrange(125_000_000_000_000_000, 140_000_000_000_000_000) for _ in range(20_000)]
    samples += [rnd.randrange(0, 2**64) for _ in range(20_000)]
    # Values exercising the .5-microsecond rounding (wintime ending in 5)
    samples += [rnd.randrange(0, 2**53) * 10 + 5 for _ in range(20_000)]

    for wintime in samples:
        assert regipy_rs.convert_wintime_iso(wintime) == convert_wintime(wintime, as_json=True), wintime
        py_dt = convert_wintime(wintime, as_json=False)
        rs_dt = regipy_rs.convert_wintime_datetime(wintime)
        assert py_dt == rs_dt, wintime
        assert py_dt.isoformat() == rs_dt.isoformat(), wintime
        assert rs_dt.tzinfo is py_dt.tzinfo, wintime
