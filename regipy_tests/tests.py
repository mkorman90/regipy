import json
import os
from tempfile import mkdtemp


from regipy import NoRegistrySubkeysException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.utils import dump_hive_to_json

from regipy.recovery import apply_transaction_logs
from regipy.regdiff import compare_hives
from regipy.registry import RegistryHive, NKRecord
from regipy.cli_utils import get_filtered_subkeys


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
    assert (
        registry_hive.root.name
        == "CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}"
    )
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

    values = [x for x in run_key.iter_values(as_json=True)]
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

    values = [x for x in run_key.iter_values(as_json=True)]
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
    for subkey_count, subkey in enumerate(
        registry_hive.recurse_subkeys(as_json=True, fetch_values=False)
    ):
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


def test_system_apply_transaction_logs(
    transaction_system, system_tr_log_1, system_tr_log_2
):
    output_path = os.path.join(mkdtemp(), "recovered_hive.dat")
    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(
        transaction_system,
        primary_log_path=system_tr_log_1,
        secondary_log_path=system_tr_log_2,
        restored_hive_path=output_path,
    )
    assert recovered_dirty_pages_count == 315

    found_differences = compare_hives(transaction_system, restored_hive_path)
    assert len(found_differences) == 2511
    assert len([x for x in found_differences if x[0] == "new_subkey"]) == 2458
    assert len([x for x in found_differences if x[0] == "new_value"]) == 53


def test_system_hive_devprop_structure(system_devprop):
    registry_hive = RegistryHive(system_devprop)
    subkey = registry_hive.get_key(
        "\\ControlSet001\\Enum\\ACPI\\ACPI0003\\0\\Properties\\{83da6326-97a6-4088-9453-"
        "a1923f573b29}\\0003"
    )
    assert subkey.values_count == 1
    value = subkey.get_values()[0]
    assert value.name == "(default)"
    assert (
        value.value
        == "cmbatt.inf:db04a16c09a7808a:AcAdapter_Inst:6.3.9600.16384:ACPI\\ACPI0003"
    )
    assert value.value_type == 18


def test_system_apply_transaction_logs_2(
    transaction_usrclass, usrclass_tr_log_1, usrclass_tr_log_2
):
    output_path = os.path.join(mkdtemp(), "recovered_hive.dat")
    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(
        transaction_usrclass,
        primary_log_path=usrclass_tr_log_1,
        secondary_log_path=usrclass_tr_log_2,
        restored_hive_path=output_path,
    )
    assert recovered_dirty_pages_count == 158

    found_differences = compare_hives(transaction_usrclass, restored_hive_path)
    assert len(found_differences) == 225
    assert len([x for x in found_differences if x[0] == "new_subkey"]) == 93
    assert len([x for x in found_differences if x[0] == "new_value"]) == 132


def test_hive_serialization(ntuser_hive, temp_output_file):
    registry_hive = RegistryHive(ntuser_hive)
    dump_hive_to_json(
        registry_hive, temp_output_file, registry_hive.root, verbose=False
    )
    counter = 0
    with open(temp_output_file, "r") as dumped_hive:
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
    assert (
        registry_hive.get_key("ODBC").header
        == registry_hive.root.get_subkey("ODBC").header
    )
    assert (
        registry_hive.root.get_subkey("ODBC").header
        == registry_hive.get_key("SOFTWARE\\ODBC").header
    )


def test_get_subkey_errors(software_hive):
    registry_hive = RegistryHive(software_hive)
    # Tests the NoRegistrySubkeysException that suppose to be raised
    try:
        registry_hive.get_key("ODBC").get_subkey("xyz")
        assert False
    except NoRegistrySubkeysException:
        assert True

    # Tests value if raised_on_missing is set to False
    assert (
        registry_hive.get_key("ODBC").get_subkey("xyz", raise_on_missing=False) is None
    )


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
    for subkey_count, entry in enumerate(
        get_filtered_subkeys(registry_hive, registry_hive.root, fetch_values=False)
    ):
        assert entry.values == []
    assert subkey_count == 1811
