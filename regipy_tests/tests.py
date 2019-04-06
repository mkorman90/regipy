import json
import os
from tempfile import mkdtemp

import pytest

from regipy.recovery import apply_transaction_logs
from regipy.regdiff import compare_hives
from regipy.registry import RegistryHive, NKRecord


def test_parse_header(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)

    assert isinstance(registry_hive, RegistryHive)
    assert registry_hive.header.primary_sequence_num == 744
    assert registry_hive.header.secondary_sequence_num == 744
    assert registry_hive.header.last_modification_time == 129782982453388850
    assert registry_hive.header.major_version == 1
    assert registry_hive.header.minor_version == 3
    assert registry_hive.header.root_key_offset == 32
    assert registry_hive.header.hive_bins_data_size == 733184
    assert registry_hive.header.minor_version == 3
    assert registry_hive.header.file_name == '?\\C:\\Users\\vibranium\\ntuser.dat'
    assert registry_hive.header.checksum == 448714443


def test_parse_root_key(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)

    assert isinstance(registry_hive, RegistryHive)
    assert isinstance(registry_hive.root, NKRecord)
    assert registry_hive.root.name == 'CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}'
    assert registry_hive.root.subkey_count == 11
    assert dict(registry_hive.root.header) == {
        'access_bits': b'\x00\x00\x00\x00',
        'class_name_offset': 4294967295,
        'class_name_size': 0,
        'flags': b',\x00',
        'key_name_size': 52,
        'key_name_string': b'CMI-CreateHive{6A1C4018-979D-4291-A7DC-7AED1C75B67C}',
        'largest_sk_class_name': 0,
        'largest_sk_name': 40,
        'largest_value_name': 0,
        'last_modified': 129780243434537497,
        'largest_value_data': 0,
        'parent_key_offset': 1656,
        'security_list_offset': 1376,
        'subkey_count': 11,
        'subkeys_list_offset': 73760,
        'values_count': 0,
        'values_list_offset': 4294967295,
        'volatile_subkey_count': 2,
        'volatile_subkeys_list_offset': 2147486280
    }


def test_find_keys_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    run_key = registry_hive.get_key(r'\Software\Microsoft\Windows\CurrentVersion\Run')

    assert run_key.name == 'Run'
    assert run_key.header.last_modified == 129779615948377168

    values = [x for x in run_key.iter_values(as_json=True)]
    assert values[0].name == 'Sidebar'
    assert values[0].value_type == 'REG_EXPAND_SZ'


def test_ntuser_timeline(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    # TODO
    pass


def test_regdiff(ntuser_hive, second_hive_path):
    found_differences = compare_hives(ntuser_hive, second_hive_path)
    assert len(found_differences) == 2
    assert len([x for x in found_differences if x[0] == 'new_subkey']) == 1
    assert len([x for x in found_differences if x[0] == 'new_value']) == 1


def test_ntuser_emojis(transaction_ntuser):
    # There are some cases where the Registry stores utf-16 emojis as subkey names :)
    registry_hive = RegistryHive(transaction_ntuser)
    international = registry_hive.get_key(r'\Control Panel\International')
    subkeys = [x.name for x in international.iter_subkeys()]
    assert subkeys == ['Geo', 'User Profile', 'User Profile System Backup', '🌎🌏🌍']


def test_recurse_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    EXPECTED_KEYS = ['path', 'subkey_name', 'timestamp', 'values', 'values_count']

    value_types = {
        'REG_BINARY': 0,
        'REG_DWORD': 0,
        'REG_EXPAND_SZ': 0,
        'REG_MULTI_SZ': 0,
        'REG_NONE': 0,
        'REG_QWORD': 0,
        'REG_SZ': 0
    }

    subkey_count = 0
    values_count = 0
    for subkey in registry_hive.recurse_subkeys(as_json=True):
        subkey_values = subkey.values
        subkey_count += 1
        values_count += len(subkey_values or [])
        if subkey_values:
            for x in subkey_values:
                value_types[x['value_type']] += 1

    assert subkey_count == 2318
    assert values_count == 4612
    assert value_types == {
        'REG_BINARY': 619,
        'REG_DWORD': 1516,
        'REG_EXPAND_SZ': 100,
        'REG_MULTI_SZ': 309,
        'REG_NONE': 141,
        'REG_QWORD': 57,
        'REG_SZ': 1870
    }


def test_recurse_amcache(amcache_hive):
    registry_hive = RegistryHive(amcache_hive)

    value_types = {
        'REG_BINARY': 0,
        'REG_DWORD': 0,
        'REG_EXPAND_SZ': 0,
        'REG_MULTI_SZ': 0,
        'REG_NONE': 0,
        'REG_QWORD': 0,
        'REG_SZ': 0
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
    assert subkey_count == 2118
    assert values_count == 17546
    assert value_types == {
        'REG_BINARY': 56,
        'REG_DWORD': 1656,
        'REG_EXPAND_SZ': 0,
        'REG_MULTI_SZ': 140,
        'REG_NONE': 0,
        'REG_QWORD': 1255,
        'REG_SZ': 14439
    }


def test_ntuser_apply_transaction_logs(transaction_ntuser, transaction_log):
    output_path = os.path.join(mkdtemp(), 'recovered_hive.dat')
    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(transaction_ntuser, transaction_log,
                                                                             restored_hive_path=output_path)
    assert recovered_dirty_pages_count == 132

    found_differences = compare_hives(transaction_ntuser, restored_hive_path)
    assert len(found_differences) == 587
    assert len([x for x in found_differences if x[0] == 'new_subkey']) == 527
    assert len([x for x in found_differences if x[0] == 'new_value']) == 59


def test_hive_serialization(ntuser_hive, temp_output_file):
    registry_hive = RegistryHive(ntuser_hive)
    registry_hive.dump_hive_to_json(temp_output_file, registry_hive.root, verbose=False)
    counter = 0
    with open(temp_output_file, 'r') as dumped_hive:
        for x in dumped_hive.readlines():
            assert json.loads(x)
            counter += 1
    assert counter == 2318
