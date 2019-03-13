import pytest

from regipy.plugins import NTUserPersistencePlugin, UserAssistPlugin, AmCachePlugin
from regipy.plugins.software.persistence import SoftwarePersistencePlugin
from regipy.plugins.system.computer_name import ComputerNamePlugin
from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy.registry import RegistryHive


def test_shimcache_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    shimcache_plugin_result = ShimCachePlugin(registry_hive, as_json=True).run()
    assert len(shimcache_plugin_result) == 660
    assert shimcache_plugin_result[0] == {
        'last_mod_date': '2011-01-12T12:08:00+00:00',
        'path': '\\??\\C:\\Program Files\\McAfee\\VirusScan Enterprise\\mfeann.exe',
        'exec_flag': 'True'
    }


def test_computer_name_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    computer_name_plugin_result = ComputerNamePlugin(registry_hive, as_json=True).run()

    assert computer_name_plugin_result == [
        {'name': 'WKS-WIN732BITA',
         'timestamp': '2010-11-10T17:18:08.718750+00:00'
         },
        {'name': 'WIN-V5T3CSP8U4H',
         'timestamp': '2010-11-10T18:17:36.968750+00:00'
         }
    ]


def test_persistence_plugin_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    persistence_plugin_result = NTUserPersistencePlugin(registry_hive, as_json=True).run()
    assert persistence_plugin_result == {
        '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': {
            'timestamp': '2012-04-03T21:19:54.837716+00:00',
            'values': [
                {'name': 'Sidebar',
                 'value_type': 'REG_EXPAND_SZ',
                 'value': '%ProgramFiles%\\Windows Sidebar\\Sidebar.exe /autoRun', 'is_corrupted': False
                 }
            ]
        }
    }


def test_persistence_plugin_software(software_hive):
    registry_hive = RegistryHive(software_hive)
    persistence_plugin_result = SoftwarePersistencePlugin(registry_hive, as_json=True).run()
    assert persistence_plugin_result == {
        '\\Microsoft\\Windows\\CurrentVersion\\Run':
            {'timestamp': '2012-04-04T01:54:23.669836+00:00',
             'values': [
                 {
                     'name': 'VMware Tools',
                     'value_type': 'REG_SZ',
                     'value': '"C:\\Program Files\\VMware\\VMware Tools\\VMwareTray.exe"',
                     'is_corrupted': False
                 },
                 {
                     'name': 'VMware User Process',
                     'value_type': 'REG_SZ',
                     'value': '"C:\\Program Files\\VMware\\VMware Tools\\VMwareUser.exe"',
                     'is_corrupted': False
                 },
                 {
                     'name': 'Adobe ARM',
                     'value_type': 'REG_SZ',
                     'value': '"C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"',
                     'is_corrupted': False
                 },
                 {
                     'name': 'McAfeeUpdaterUI',
                     'value_type': 'REG_SZ',
                     'value': '"C:\\Program Files\\McAfee\\Common Framework\\udaterui.exe" /StartedFromRunKey',
                     'is_corrupted': False
                 },
                 {
                     'name': 'ShStatEXE',
                     'value_type': 'REG_SZ',
                     'value': '"C:\\Program Files\\McAfee\\VirusScan Enterprise\\SHSTAT.EXE" /STANDALONE',
                     'is_corrupted': False
                 },
                 {
                     'name': 'McAfee Host Intrusion Prevention Tray',
                     'value_type': 'REG_SZ',
                     'value': '"C:\\Program Files\\McAfee\\Host Intrusion Prevention\\FireTray.exe"',
                     'is_corrupted': False
                 },
                 {
                     'name': 'svchost',
                     'value_type': 'REG_SZ',
                     'value': 'c:\\windows\\system32\\dllhost\\svchost.exe',
                     'is_corrupted': False
                 }
             ]
             }
    }


def test_user_assist_plugin_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    user_assist_plugin_result = UserAssistPlugin(registry_hive, as_json=True).run()
    assert len(user_assist_plugin_result) == 62
    assert user_assist_plugin_result[-1] == {
        'name': '%PROGRAMFILES(X86)%\\Microsoft Office\\Office14\\EXCEL.EXE',
        'timestamp': '2012-04-04T15:43:14.785000+00:00',
        'run_counter': 4,
        'focus_count': 1,
        'total_focus_time_ms': 47673,
        'session_id': 0
    }
    assert user_assist_plugin_result[0] == {
        'name': '%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Welcome Center.lnk',
        'timestamp': '2012-04-03T22:06:58.124282+00:00',
        'run_counter': 14,
        'focus_count': 0,
        'total_focus_time_ms': 14,
        'session_id': 0
    }


def test_plugin_amcache(amcache_hive):
    registry_hive = RegistryHive(amcache_hive)
    amcache_plugin_result = AmCachePlugin(registry_hive, as_json=True).run()
    assert len(amcache_plugin_result) == 1120
    assert amcache_plugin_result[0] == {
        'timestamp': '2017-08-03T11:34:04.654176+00:00',
        'full_path': 'c:\\users\\user\\appdata\\local\\microsoft\\onedrive\\17.3.6943.0625\\FileSyncFAL.dll',
        'program_id': '659b3b63c514582e025e19d3276899150000ffff',
        'sha1': '818b581a471c1c6833839d35a9d6f3544f6a9c92',
        'last_modified_timestamp_2': '2017-08-01T12:05:02.598866+00:00',
        'type': 'win_8+_amcache'
    }
