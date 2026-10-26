import io
import json
import os
import struct
import types
from tempfile import mkdtemp, mktemp

import pytest

from regipy import NoRegistrySubkeysException
from regipy.cli_utils import get_filtered_subkeys
from regipy.exceptions import RegistryRecoveryException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.system.external.ShimCacheParser import get_shimcache_entries
from regipy.plugins.utils import dump_hive_to_json
from regipy.recovery import _marvin32, _scan_hvle_entries, apply_transaction_logs
from regipy.regdiff import compare_hives
from regipy.registry import NKRecord, RegistryHive
from regipy.structs import HVLE_BLOCK_HEADER_SIZE, REGF_HEADER_SIZE, TRANSACTION_LOG


def test_parse_header(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)

    assert isinstance(registry_hive, RegistryHive)
    assert registry_hive.header.primary_sequence_num == 749
    assert registry_hive.header.secondary_sequence_num == 749
    assert registry_hive.header.last_modification_time == 129782982453388850
    assert registry_hive.header.major_version == 1
    assert registry_hive.header.minor_version == 3
    assert registry_hive.header.root_key_offset == 32
    assert registry_hive.header.hive_bins_data_size == 733184
    assert registry_hive.header.minor_version == 3
    assert registry_hive.header.file_name == "?\\C:\\Users\\vibranium\\ntuser.dat"
    assert registry_hive.header.checksum == 476614345


def test_parse_root_key(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)

    assert isinstance(registry_hive, RegistryHive)
    assert isinstance(registry_hive.root, NKRecord)
    assert registry_hive.root.name == "CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}"
    assert registry_hive.root.subkey_count == 11
    assert dict(registry_hive.root.header) == {
        "access_bits": b"\x02\x00\x00\x00",
        "class_name_offset": 4294967295,
        "class_name_size": 0,
        "flags": {
            "KEY_COMP_NAME": True,
            "KEY_HIVE_ENTRY": True,
            "KEY_HIVE_EXIT": False,
            "KEY_NO_DELETE": True,
            "KEY_PREDEF_HANDLE": False,
            "KEY_SYM_LINK": False,
            "KEY_VOLATILE": False,
        },
        "key_name_size": 52,
        "key_name_string": b"CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}",
        "largest_sk_class_name": 0,
        "largest_sk_name": 40,
        "largest_value_name": 0,
        "last_modified": 129780243434537497,
        "largest_value_data": 0,
        "parent_key_offset": 1968,
        "security_key_offset": 1376,
        "subkey_count": 11,
        "subkeys_list_offset": 73760,
        "values_count": 0,
        "values_list_offset": 4294967295,
        "volatile_subkey_count": 0,
        "volatile_subkeys_list_offset": 4294967295,
    }


def test_find_keys_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    run_key = registry_hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Run")

    assert run_key.name == "Run"
    assert run_key.header.last_modified == 129779615948377168

    values = list(run_key.iter_values(as_json=True))
    assert values[0].name == "Sidebar"
    assert values[0].value_type == "REG_EXPAND_SZ"


def test_find_keys_partial_ntuser_hive(ntuser_software_partial):
    registry_hive = RegistryHive(
        ntuser_software_partial,
        hive_type=NTUSER_HIVE_TYPE,
        partial_hive_path=r"\Software",
    )

    run_key = registry_hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Run")
    assert run_key.name == "Run"
    assert run_key.header.last_modified == 132024690510209250

    values = list(run_key.iter_values(as_json=True))
    assert values[0].name == "OneDrive"
    assert values[0].value_type == "REG_SZ"


def test_regdiff(ntuser_hive, second_hive_path):
    found_differences = compare_hives(ntuser_hive, second_hive_path, verbose=True)
    assert len(found_differences) == 7
    assert len([x for x in found_differences if x[0] == "new_subkey"]) == 6
    assert len([x for x in found_differences if x[0] == "new_value"]) == 1


def test_ntuser_emojis(transaction_ntuser):
    # There are some cases where the Registry stores utf-16 emojis as subkey names :)
    registry_hive = RegistryHive(transaction_ntuser)
    international = registry_hive.get_key(r"\Control Panel\International")
    subkeys = [x.name for x in international.iter_subkeys()]
    assert subkeys == ["Geo", "User Profile", "User Profile System Backup", "🌎🌏🌍"]


def test_recurse_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)

    value_types = {
        "REG_BINARY": 0,
        "REG_DWORD": 0,
        "REG_EXPAND_SZ": 0,
        "REG_MULTI_SZ": 0,
        "REG_NONE": 0,
        "REG_QWORD": 0,
        "REG_SZ": 0,
    }

    subkey_count = 0
    values_count = 0
    for subkey in registry_hive.recurse_subkeys(as_json=True):
        subkey_values = subkey.values
        subkey_count += 1
        values_count += len(subkey_values or [])
        if subkey_values:
            for x in subkey_values:
                value_types[x["value_type"]] += 1

    assert subkey_count == 1812
    assert values_count == 4094
    assert value_types == {
        "REG_BINARY": 531,
        "REG_DWORD": 1336,
        "REG_EXPAND_SZ": 93,
        "REG_MULTI_SZ": 303,
        "REG_NONE": 141,
        "REG_QWORD": 54,
        "REG_SZ": 1636,
    }


def test_recurse_partial_ntuser(ntuser_software_partial):
    registry_hive = RegistryHive(
        ntuser_software_partial,
        hive_type=NTUSER_HIVE_TYPE,
        partial_hive_path=r"\Software",
    )
    for subkey_count, subkey in enumerate(registry_hive.recurse_subkeys(as_json=True)):
        assert subkey.actual_path.startswith(registry_hive.partial_hive_path)
    assert subkey_count == 6395


def test_recurse_ntuser_without_fetching_values(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    for subkey_count, subkey in enumerate(registry_hive.recurse_subkeys(as_json=True, fetch_values=False)):
        assert subkey.values == []
        assert subkey.values_count >= 0
    assert subkey_count == 1811


def test_recurse_amcache(amcache_hive):
    registry_hive = RegistryHive(amcache_hive)

    value_types = {
        "REG_BINARY": 0,
        "REG_DWORD": 0,
        "REG_EXPAND_SZ": 0,
        "REG_MULTI_SZ": 0,
        "REG_NONE": 0,
        "REG_QWORD": 0,
        "REG_SZ": 0,
    }
    subkey_count = 0
    values_count = 0
    for subkey in registry_hive.recurse_subkeys():
        subkey_count += 1
        subkey_values = subkey.values
        values_count += len(subkey_values or [])
        if subkey_values:
            for x in subkey_values:
                value_types[x.value_type] += 1
    assert subkey_count == 2105
    assert values_count == 17539
    assert value_types == {
        "REG_BINARY": 56,
        "REG_DWORD": 1656,
        "REG_EXPAND_SZ": 0,
        "REG_MULTI_SZ": 140,
        "REG_NONE": 0,
        "REG_QWORD": 1254,
        "REG_SZ": 14433,
    }


def test_ntuser_apply_transaction_logs(transaction_ntuser, transaction_log):
    output_path = os.path.join(mkdtemp(), "recovered_hive.dat")
    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(
        transaction_ntuser, transaction_log, restored_hive_path=output_path
    )
    assert recovered_dirty_pages_count == 132

    found_differences = compare_hives(transaction_ntuser, restored_hive_path)
    assert len(found_differences) == 588
    assert len([x for x in found_differences if x[0] == "new_subkey"]) == 527
    assert len([x for x in found_differences if x[0] == "new_value"]) == 60


def test_system_apply_transaction_logs(transaction_system, system_tr_log_1, system_tr_log_2):
    output_path = os.path.join(mkdtemp(), "recovered_hive.dat")
    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(
        transaction_system,
        primary_log_path=system_tr_log_1,
        secondary_log_path=system_tr_log_2,
        restored_hive_path=output_path,
    )
    assert recovered_dirty_pages_count == 315

    found_differences = compare_hives(transaction_system, restored_hive_path)
    # The previously locked count (2507) was generated with the older sequence chain
    # applied last, so stale pages from the older log clobbered newer ones (gh #352).
    # With the spec-correct order (earlier chain first, then the later one) the
    # restored hive is larger: 16 additional subkeys and one hive bins data size
    # difference (the hive grows to the last applied entry's declared bin size).
    assert len(found_differences) == 2519
    assert len([x for x in found_differences if x[0] == "new_subkey"]) == 2472
    assert len([x for x in found_differences if x[0] == "new_value"]) == 46
    assert len([x for x in found_differences if x[0] == "different_hive_bin_data_size"]) == 1


def test_system_hive_devprop_structure(system_devprop):
    registry_hive = RegistryHive(system_devprop)
    subkey = registry_hive.get_key(
        "\\ControlSet001\\Enum\\ACPI\\ACPI0003\\0\\Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0003"
    )
    assert subkey.values_count == 1
    value = subkey.get_values()[0]
    assert value.name == "(default)"
    assert value.value == "cmbatt.inf:db04a16c09a7808a:AcAdapter_Inst:6.3.9600.16384:ACPI\\ACPI0003"
    assert value.value_type == 18


def test_system_apply_transaction_logs_2(transaction_usrclass, usrclass_tr_log_1, usrclass_tr_log_2):
    output_path = os.path.join(mkdtemp(), "recovered_hive.dat")
    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(
        transaction_usrclass,
        primary_log_path=usrclass_tr_log_1,
        secondary_log_path=usrclass_tr_log_2,
        restored_hive_path=output_path,
    )
    assert recovered_dirty_pages_count == 158

    found_differences = compare_hives(transaction_usrclass, restored_hive_path)
    # Was 225 with the older sequence chain applied last (gh #352): stale pages from
    # the older log clobbered 119 newer subkeys. Spec-correct order recovers them all.
    assert len(found_differences) == 73
    assert len([x for x in found_differences if x[0] == "new_subkey"]) == 33
    assert len([x for x in found_differences if x[0] == "new_value"]) == 40


def test_parse_indirect_block_output_bounded_by_hive_size():
    """
    The value size (vk.data_size) and the segment offsets of an indirect ("db")
    block both come from the hive and may be corrupt. A crafted hive could declare
    up to 0x7FFFFFFF bytes and repeat segment offsets, amplifying a small file into
    gigabytes of memory. The reassembled value must be bounded by the number of
    segments in the db block header and by the size of the hive file itself.
    """
    db_cell = b"db" + struct.pack("<HI", 65535, 8)  # number_of_segments, offset_to_list
    list_start = REGF_HEADER_SIZE + 4 + 8
    segments = 100
    list_end = list_start + 4 * segments
    # A file that declares 0x7FFFFFFF bytes of value data while holding ~20 KB:
    # a segment list repeating one offset plus a single 16,344-byte data area
    file = bytearray(list_start) + struct.pack("<I", list_end - (REGF_HEADER_SIZE + 4)) * segments + b"\x42" * 0x3FD8
    file = bytes(file)
    value = types.SimpleNamespace(value=db_cell, size=0x7FFFFFFF)

    data = NKRecord._parse_indirect_block(io.BytesIO(file), value)
    assert len(data) == len(file)


def _build_hvle_log(sequence_number, hive_bin_size, dirty_pages, log_size=None):
    """Build a crafted single-entry HvLE transaction log (512 zero bytes of REGF
    header plus one HvLE entry) with valid Marvin32 hashes.

    :param sequence_number: the entry's sequence number
    :param hive_bin_size: the entry's declared hive bins data size
    :param dirty_pages: list of (offset, declared_size, data) page references -
        the entry holds *data* bytes for a page but declares *declared_size*,
        so a reference can be inflated to test the corrupt-references path
    :param log_size: override for the entry's declared Size field (defaults to
        the true entry size); the zero-size rejection test passes 0
    """
    references = [{"offset": offset, "size": declared_size} for offset, declared_size, _ in dirty_pages]
    page_data = b"".join(data for _, _, data in dirty_pages)
    if log_size is None:
        log_size = HVLE_BLOCK_HEADER_SIZE + 8 * len(dirty_pages) + len(page_data)

    body = (
        TRANSACTION_LOG.build(
            {
                "signature": b"HvLE",
                "log_size": log_size,
                "flags": 0,
                "sequence_number": sequence_number,
                "hive_bin_size": hive_bin_size,
                "dirty_pages_count": len(dirty_pages),
                "hash_1": 0,
                "hash_2": 0,
                "dirty_pages_references": references,
            }
        )
        + page_data
    )

    # Hash-1 covers everything from the first page reference on; Hash-2 covers
    # the first 32 bytes of the entry, which include Hash-1, so the two are
    # computed in that order and patched into the built header.
    hash_1 = _marvin32(body[HVLE_BLOCK_HEADER_SIZE:])
    hash_2 = _marvin32(body[:24] + struct.pack("<Q", hash_1))
    return b"\x00" * 512 + body[:24] + struct.pack("<QQ", hash_1, hash_2) + body[40:]


def test_transaction_log_hvle_zero_log_size_rejected(transaction_ntuser):
    """
    An HvLE block whose log_size is smaller than the 40-byte block header used to
    make _parse_hvle_block re-parse the same block forever (infinite loop).
    Such a block must be rejected with a RegistryRecoveryException.
    """
    log_path = mktemp()
    with open(log_path, "wb") as f:
        f.write(_build_hvle_log(sequence_number=5, hive_bin_size=0x10000, dirty_pages=[], log_size=0))

    with pytest.raises(RegistryRecoveryException, match="invalid log_size"):
        apply_transaction_logs(transaction_ntuser, log_path, restored_hive_path=os.path.join(mkdtemp(), "restored.dat"))


def test_transaction_log_dirty_page_outside_hive_rejected(transaction_ntuser):
    """
    A dirty page entry pointing outside of the primary hive must be rejected.
    Without the check the restored hive buffer (and the file written to disk)
    would balloon up to the 32-bit offset (up to ~4 GiB) from a sub-KiB log.

    The crafted entry is structurally valid and carries valid Marvin32 hashes,
    so it reaches the bounds check at apply time: the 4096-byte page image sits
    inside the entry, but its target offset (~4 GiB) is far beyond the hive,
    and the entry's declared hive bin size (0x10000) is too small to cover it.
    """
    log_path = mktemp()
    # The 4096-byte page image is inside the entry (the hashes are valid), but
    # its target offset (~4 GiB) is far beyond the hive, and the entry's
    # declared hive bin size (0x10000) is too small to cover it.
    page_data = b"\x41" * 4096
    with open(log_path, "wb") as f:
        f.write(
            _build_hvle_log(sequence_number=5, hive_bin_size=0x10000, dirty_pages=[(0x7FFFFF00, len(page_data), page_data)])
        )

    with pytest.raises(RegistryRecoveryException, match="points outside of the hive"):
        apply_transaction_logs(transaction_ntuser, log_path, restored_hive_path=os.path.join(mkdtemp(), "restored.dat"))


def test_transaction_log_corrupt_page_references_stop_recovery(transaction_ntuser):
    """
    A hash-valid crafted entry can declare a page size that exceeds the page data
    held by the entry (the hash only proves the bytes are intact, not that the
    declared size fits). Such an entry must stop recovery cleanly: no pages are
    applied and the restored hive is byte-identical to the original.
    """
    log_path = mktemp()
    with open(log_path, "wb") as f:
        # Declares 512 bytes for its page, holds only 16.
        f.write(_build_hvle_log(sequence_number=5, hive_bin_size=0x10000, dirty_pages=[(0x7FFFFF00, 512, b"\x00" * 16)]))

    output_path = os.path.join(mkdtemp(), "restored.dat")
    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(
        transaction_ntuser, log_path, restored_hive_path=output_path
    )
    assert recovered_dirty_pages_count == 0
    with open(transaction_ntuser, "rb") as f1, open(restored_hive_path, "rb") as f2:
        assert f1.read() == f2.read()


def test_transaction_log_dirt_short_vector_rejected(transaction_ntuser):
    """
    The DIRT dirty page vector must match the hive's hbins_data_size (190 bytes for
    the transaction NTUSER fixture). A shorter log must be rejected cleanly instead
    of failing mid-recovery with an IndexError.
    """
    log_path = mktemp()
    log = bytearray(512) + b"DIRT" + b"\x00" * 64  # 64 < 190
    with open(log_path, "wb") as f:
        f.write(bytes(log))

    with pytest.raises(RegistryRecoveryException, match="dirty page vector"):
        apply_transaction_logs(transaction_ntuser, log_path, restored_hive_path=os.path.join(mkdtemp(), "restored.dat"))


def test_system_apply_transaction_logs_order_independent(transaction_system, system_tr_log_1, system_tr_log_2):
    """
    Which log holds the earlier sequence chain is a property of the logs, not of
    the caller's argument order. Previously the secondary log was always applied
    first (gh #352), so applying (LOG1, LOG2) and (LOG2, LOG1) produced different
    restored hives - with the older chain applied last, its stale pages clobbered
    newer ones. Both argument orders must now yield the identical restored hive.
    """

    # The fixture logs form a continuous chain: LOG1 (2107-2110) then LOG2 (2111-2130),
    # so the expected page count is the sum of the dirty pages of both logs.
    expected_pages = sum(len(pages) for _, _, pages in _scan_hvle_entries(system_tr_log_1)) + sum(
        len(pages) for _, _, pages in _scan_hvle_entries(system_tr_log_2)
    )

    output_12 = os.path.join(mkdtemp(), "recovered_12.dat")
    output_21 = os.path.join(mkdtemp(), "recovered_21.dat")
    _, count_12 = apply_transaction_logs(
        transaction_system,
        primary_log_path=system_tr_log_1,
        secondary_log_path=system_tr_log_2,
        restored_hive_path=output_12,
    )
    _, count_21 = apply_transaction_logs(
        transaction_system,
        primary_log_path=system_tr_log_2,
        secondary_log_path=system_tr_log_1,
        restored_hive_path=output_21,
    )

    assert count_12 == expected_pages == count_21
    with open(output_12, "rb") as f1, open(output_21, "rb") as f2:
        assert f1.read() == f2.read()


def test_ntuser_apply_transaction_logs_gap_stops_recovery(transaction_ntuser, transaction_log, transaction_log_2):
    """
    The two bundled NTUSER logs do not form a continuous chain: log2 holds a single
    entry with sequence 562 (stale relative to the hive's secondary sequence 566)
    and log1 holds entries 566-588. Per the registry file format specification,
    recovery stops when an entry N is not followed by N + 1, so only the older
    chain (log2) is applied - in either argument order.
    """

    expected_pages = sum(len(pages) for _, _, pages in _scan_hvle_entries(transaction_log_2))

    for primary, secondary in ((transaction_log, transaction_log_2), (transaction_log_2, transaction_log)):
        _, count = apply_transaction_logs(
            transaction_ntuser,
            primary_log_path=primary,
            secondary_log_path=secondary,
            restored_hive_path=os.path.join(mkdtemp(), "recovered.dat"),
        )
        assert count == expected_pages


def test_transaction_log_hash_mismatch_stops_recovery(transaction_system, system_tr_log_1, system_tr_log_2):
    """
    Hash-1 covers everything from the first page reference of an entry on. A byte
    of page data flipped in the first entry of LOG2 (sequence 2111) must make
    recovery stop at that entry: only the entries of LOG1 are applied, and no
    exception is raised (a failed hash stops recovery; it does not abort it).
    """

    expected_pages = sum(len(pages) for _, _, pages in _scan_hvle_entries(system_tr_log_1))

    with open(system_tr_log_2, "rb") as f:
        log_data = bytearray(f.read())

    # Corrupt the first page-data byte of the first entry (at 512 + 40 + 8 * n_refs)
    (dirty_pages_count,) = struct.unpack_from("<I", log_data, 512 + 20)
    data_start = 512 + 40 + 8 * dirty_pages_count
    log_data[data_start] ^= 0xFF

    corrupt_log_path = mktemp()
    with open(corrupt_log_path, "wb") as f:
        f.write(bytes(log_data))

    _, count = apply_transaction_logs(
        transaction_system,
        primary_log_path=system_tr_log_1,
        secondary_log_path=corrupt_log_path,
        restored_hive_path=os.path.join(mkdtemp(), "recovered.dat"),
    )
    assert count == expected_pages


def test_hive_serialization(ntuser_hive, temp_output_file):
    registry_hive = RegistryHive(ntuser_hive)
    dump_hive_to_json(registry_hive, temp_output_file, registry_hive.root, verbose=False)
    counter = 0
    with open(temp_output_file) as dumped_hive:
        for x in dumped_hive.readlines():
            assert json.loads(x)
            counter += 1
    assert counter == 1812


def test_get_key(software_hive):
    """
    # Refers to https://github.com/mkorman90/regipy/issues/144
    """
    registry_hive = RegistryHive(software_hive)
    # We verify the registry headers are similar, because this is the same subkey.
    assert registry_hive.get_key("ODBC").header == registry_hive.root.get_subkey("ODBC").header
    assert registry_hive.root.get_subkey("ODBC").header == registry_hive.get_key("SOFTWARE\\ODBC").header


def test_get_subkey_errors(software_hive):
    registry_hive = RegistryHive(software_hive)
    # Tests the NoRegistrySubkeysException that suppose to be raised
    try:
        registry_hive.get_key("ODBC").get_subkey("xyz")
        raise AssertionError()
    except NoRegistrySubkeysException:
        assert True

    # Tests value if raised_on_missing is set to False
    assert registry_hive.get_key("ODBC").get_subkey("xyz", raise_on_missing=False) is None


def test_parse_security_info(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    run_key = registry_hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Run")

    security_key_info = run_key.get_security_key_info()
    assert security_key_info["owner"] == "S-1-5-18"
    assert security_key_info["group"] == "S-1-5-18"
    assert len(security_key_info["dacl"]) == 4
    assert security_key_info["dacl"][0] == {
        "access_mask": {
            "ACCESS_SYSTEM_SECURITY": False,
            "DELETE": True,
            "GENERIC_ALL": False,
            "GENERIC_EXECUTE": False,
            "GENERIC_READ": False,
            "GENERIC_WRITE": False,
            "MAXIMUM_ALLOWED": False,
            "READ_CONTROL": True,
            "SYNCHRONIZE": False,
            "WRITE_DAC": True,
            "WRITE_OWNER": True,
        },
        "ace_type": "ACCESS_ALLOWED",
        "flags": {
            "CONTAINER_INHERIT_ACE": True,
            "INHERIT_ONLY_ACE": False,
            "NO_PROPAGATE_INHERIT_ACE": False,
            "OBJECT_INHERIT_ACE": True,
        },
        "sid": "S-1-5-21-2036804247-3058324640-2116585241-1673",
    }

    dacl_sids = [x["sid"] for x in security_key_info["dacl"]]
    assert dacl_sids == [
        "S-1-5-21-2036804247-3058324640-2116585241-1673",
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-12",
    ]


def test_parse_filetime_value(system_hive_with_filetime):
    registry_hive = RegistryHive(system_hive_with_filetime)
    subkey = registry_hive.get_key(
        r"\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.2"
        r"0\200608767007B7C08A6A&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064"
    )
    val = subkey.get_value("(default)", as_json=True)
    assert val == "2020-03-17T14:02:38.955490+00:00"


def test_ntuser_filtered_timestamps_do_not_fetch_values(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    for subkey_count, entry in enumerate(
        get_filtered_subkeys(
            registry_hive,
            registry_hive.root,
            fetch_values=False,
            start_date="2012-04-03T00:00:00.000000",
            end_date="2012-04-03T23:59:59.999999",
        )
    ):
        assert entry.values == []
    assert subkey_count == 1489


def test_ntuser_filtered_timestamps_fetch_values(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    for subkey_count, entry in enumerate(
        get_filtered_subkeys(
            registry_hive,
            registry_hive.root,
            fetch_values=True,
            start_date="2012-04-03T00:00:00.000000",
            end_date="2012-04-03T23:59:59.999999",
        )
    ):
        # values_count is parsed from the subkey header, so this test if effective.
        if entry.values_count > 0:
            assert len(entry.values) == entry.values_count
    assert subkey_count == 1489


def test_ntuser_filtered_timestamps_no_filter(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    for subkey_count, entry in enumerate(get_filtered_subkeys(registry_hive, registry_hive.root, fetch_values=False)):
        assert entry.values == []
    assert subkey_count == 1811


def test_inline_reg_sz_value_is_decoded(system_hive):
    # Values with the inline-data flag (data_size >= 0x80000000) store their
    # data in the VK data_offset field itself. Regression test: these used to
    # be returned as the raw data_offset integer instead of a decoded string.
    registry_hive = RegistryHive(system_hive)
    subkey = registry_hive.get_key(r"\ControlSet001\Control\Class\{0475BB51-5A02-4EE0-B36C-29040FAD2650}")
    assert subkey.get_value("NoDisplayClass") == "1"
    assert subkey.get_value("Class") == "vm3dmp"


def test_inline_reg_binary_value_is_decoded(ntuser_hive):
    # Inline REG_BINARY values used to be returned as the raw data_offset
    # integer; they are now returned like any other binary value.
    registry_hive = RegistryHive(ntuser_hive)
    subkey = registry_hive.get_key(r"\Control Panel\Appearance")
    assert subkey.get_value("SchemeLangID") == b"\x09\x04"
    values = {value.name: value for value in subkey.iter_values(as_json=True)}
    assert values["SchemeLangID"].value == "0904"


class _ReadCountingStream:
    """Delegates to a hive stream while recording what read() is asked to return."""

    def __init__(self, stream):
        self._stream = stream
        self.max_requested = 0
        self.total_requested = 0

    def read(self, size=-1):
        if size is not None and size >= 0:
            self.max_requested = max(self.max_requested, size)
            self.total_requested += size
        return self._stream.read(size)

    def __getattr__(self, name):
        return getattr(self._stream, name)


def test_resident_values_do_not_read_hive_tail(ntuser_hive):
    # Regression test for #350. Resident values (data_size >= 0x80000000) store
    # their data inline in the VK data_offset field and have no out-of-line
    # data cell. read_value used to pass the flagged data_size to stream.read(),
    # so every resident value (1901 of the 4094 in this hive) asked the stream
    # for ~2 GiB, copying the entire tail of the hive into memory and discarding it.
    registry_hive = RegistryHive(ntuser_hive)
    tracker = _ReadCountingStream(registry_hive._stream)
    registry_hive._stream = tracker  # type: ignore[assignment]
    registry_hive.root._stream = tracker  # type: ignore[assignment]

    total_values = 0
    for subkey in registry_hive.recurse_subkeys(as_json=True):
        total_values += len(subkey.values)

    assert total_values == 4094
    # Before the fix, the first resident value alone requested 0x80000000 | n bytes.
    assert tracker.max_requested < 0x80000000
    # All reads combined must stay bounded by the hive size (the hive's real
    # out-of-line value data is ~263 KiB), not by the hive tail per resident value.
    assert tracker.total_requested < 2 * os.path.getsize(ntuser_hive)


def test_resident_values_of_all_types_are_decoded(ntuser_hive):
    # Resident (inline) values of the common types must be decoded from the
    # VK data_offset field, which holds their payload for them. REG_BINARY is
    # covered by test_inline_reg_binary_value_is_decoded.
    registry_hive = RegistryHive(ntuser_hive)

    # Resident REG_DWORD: the 32-bit value is stored in the data_offset field.
    assert registry_hive.get_key(r"\Console").get_value("ColorTable01") == 0x800000
    # Resident REG_SZ (default value, 2 zero bytes -> empty string).
    assert registry_hive.get_key(r"\AppEvents\Schemes\Apps\.Default\AppGPFault\.Current").get_value() == ""
    # Resident REG_EXPAND_SZ.
    assert (
        registry_hive.get_key(r"\Software\Microsoft\Windows\CurrentVersion\Themes\DefaultVisualStyleOff").get_value(
            "InstallVisualStyle"
        )
        == ""
    )
    # Resident REG_MULTI_SZ (no entries).
    assert (
        registry_hive.get_key(r"\Software\Microsoft\Cryptography\CertificateTemplateCache\Administrator").get_value(
            "msPKI-Supersede-Templates"
        )
        == []
    )


def test_resident_unknown_type_keeps_legacy_buffer_read(sam_hive):
    # This default value has an unknown type (513) and the resident flag set.
    # iter_values has no resident branch for unknown types: the final else
    # consumes the raw buffer that read_value returns. read_value therefore
    # keeps the original read for such values so the output stays byte-identical
    # to earlier versions and to the Rust backend (see #350).
    registry_hive = RegistryHive(sam_hive)
    values = list(registry_hive.get_key(r"\SAM\Domains\Account\Groups\Names\None").iter_values(as_json=True))
    assert len(values) == 1
    assert values[0].name == "(default)"
    assert values[0].value_type == "513"
    assert isinstance(values[0].value, str)
    assert len(values[0].value) == 256
    assert values[0].value.startswith("0000000000100000000000000000000034ec4d905adccf01")


def test_reg_multi_sz_without_terminator(transaction_usrclass):
    # The last string of a REG_MULTI_SZ value is not always NUL-terminated. This
    # value holds a single string without a terminator.
    registry_hive = RegistryHive(transaction_usrclass)
    subkey = registry_hive.get_key(
        r"\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps"
        r"%5CMicrosoft.Office.OneNote_17.8366.57611.0_x64__8wekyb3d8bbwe%5Cresources.pri\1d33931957c6aac\fae8ab0e"
    )
    assert subkey.get_value("LanguageList") == ["_en-US_standard_100_US_LTR_light_Desktop"]


def test_big_data_reg_multi_sz_is_reassembled(software_hive):
    # REG_MULTI_SZ values larger than 16344 bytes are stored in big-data (db)
    # segments. Regression test: these used to be parsed from the raw db
    # record bytes, producing garbage.
    registry_hive = RegistryHive(software_hive)
    subkey = registry_hive.get_key(r"\Microsoft\WBEM\CIMOM")
    mofs = subkey.get_value("Autorecover MOFs")
    assert isinstance(mofs, list)
    assert len(mofs) == 277
    assert mofs[0] == "%windir%\\system32\\wbem\\cimwin32.mof"
    assert all(mof.lower().endswith((".mof", ".mfl")) for mof in mofs)


def test_big_data_reg_sz_is_reassembled(software_hive):
    # REG_SZ values stored in big-data (db) segments span multiple 16344-byte
    # chunks and must be reassembled in order.
    registry_hive = RegistryHive(software_hive)
    subkey = registry_hive.get_key(r"\Microsoft\Office\14.0\Registration\{90140000-003D-0000-0000-0000000FF1CE}")
    values = {v.name: v.value for v in subkey.iter_values(as_json=False, trim_values=False)}
    big_values = [v for v in values.values() if isinstance(v, str) and len(v) > 0x3FD8 // 2]
    assert big_values, "expected at least one reassembled big-data string value"


def _build_nt5_shimcache(path, is_32_bit, size_or_flags):
    # Minimal Windows 2003/Vista/2008 (NT5.2) AppCompatCache blob holding a single entry.
    # 2009-05-16T06:01:28Z as a FILETIME.
    filetime = 128869272880000000
    path_bytes = path.encode("utf-16le")
    entry_size = 0x18 if is_32_bit else 0x20
    path_offset = 8 + entry_size
    header = struct.pack("<LL", 0xBADC0FFE, 1)
    if is_32_bit:
        entry = struct.pack(
            "<2H 3L 2L",
            len(path_bytes),
            len(path_bytes) + 2,
            path_offset,
            filetime & 0xFFFFFFFF,
            filetime >> 32,
            size_or_flags,
            0,
        )
    else:
        entry = struct.pack(
            "<2H 4x Q 2L 2L",
            len(path_bytes),
            len(path_bytes) + 2,
            path_offset,
            filetime & 0xFFFFFFFF,
            filetime >> 32,
            size_or_flags,
            0,
        )
    return header + entry + path_bytes + b"\x00\x00"


def test_shimcache_nt5_32bit_exec_flag():
    path = "\\??\\C:\\Windows\\system32\\notepad.exe"
    cachebin = _build_nt5_shimcache(path, is_32_bit=True, size_or_flags=0x2)
    assert list(get_shimcache_entries(cachebin, as_json=True)) == [
        {"last_mod_date": "2009-05-16T06:01:28+00:00", "path": path, "exec_flag": "True"}
    ]


def test_shimcache_nt5_64bit_file_size():
    path = "\\??\\C:\\Program Files\\App\\app.exe"
    cachebin = _build_nt5_shimcache(path, is_32_bit=False, size_or_flags=123456)
    assert list(get_shimcache_entries(cachebin, as_json=True)) == [
        {"last_mod_date": "2009-05-16T06:01:28+00:00", "path": path, "file_size": 123456}
    ]
