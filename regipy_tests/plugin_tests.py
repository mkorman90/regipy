import pytest

from regipy.plugins import NTUserPersistencePlugin, UserAssistPlugin, AmCachePlugin, WordWheelQueryPlugin, \
    UACStatusPlugin, LastLogonPlugin
from regipy.plugins.ntuser.typed_urls import TypedUrlsPlugin
from regipy.plugins.software.persistence import SoftwarePersistencePlugin
from regipy.plugins.system.computer_name import ComputerNamePlugin
from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy.registry import RegistryHive


def test_shimcache_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = ShimCachePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert len(plugin_instance.entries) == 660
    assert plugin_instance.entries[0] == {
        'last_mod_date': '2011-01-12T12:08:00+00:00',
        'path': '\\??\\C:\\Program Files\\McAfee\\VirusScan Enterprise\\mfeann.exe',
        'exec_flag': 'True'
    }


def test_computer_name_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = ComputerNamePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {'name': 'WKS-WIN732BITA',
         'timestamp': '2010-11-10T17:18:08.718750+00:00'
         },
        {'name': 'WIN-V5T3CSP8U4H',
         'timestamp': '2010-11-10T18:17:36.968750+00:00'
         }
    ]


def test_persistence_plugin_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    plugin_instance = NTUserPersistencePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
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
    plugin_instance = SoftwarePersistencePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
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
    plugin_instance = UserAssistPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert len(plugin_instance.entries) == 62
    assert plugin_instance.entries[-1] == {
        'focus_count': 1,
        'name': '%PROGRAMFILES(X86)%\\Microsoft Office\\Office14\\EXCEL.EXE',
        'run_counter': 4,
        'session_id': 0,
        'timestamp': '2012-04-04T15:43:14.785000+00:00',
        'total_focus_time_ms': 47673
    }

    assert plugin_instance.entries[50] == {
        'focus_count': 9,
        'name': 'Microsoft.Windows.RemoteDesktop',
        'run_counter': 8,
        'session_id': 0,
        'timestamp': '2012-04-03T22:06:58.124282+00:00',
        'total_focus_time_ms': 180000
    }


def test_plugin_amcache(amcache_hive):
    registry_hive = RegistryHive(amcache_hive)
    plugin_instance = AmCachePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert len(plugin_instance.entries) == 1120
    assert plugin_instance.entries[100] == {
        'full_path': 'C:\\Windows\\system32\\TPVMMondeu.dll',
        'last_modified_timestamp_2': '2017-03-17T05:06:04.002722+00:00',
        'program_id': '75a010066bb612ca7357ce31df8e9f0300000904',
        'sha1': '056f4b9d9ec9b5dc548e1b460da889e44089d76f',
        'timestamp': '2017-08-03T11:34:02.263418+00:00',
        'type': 'win_8+_amcache'
    }


def test_word_wheel_query_plugin_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    plugin_instance = WordWheelQueryPlugin(registry_hive, ntuser_hive)
    plugin_instance.run()

    assert len(plugin_instance.entries) == 6
    assert plugin_instance.entries[0] == {
        'last_write': '2012-04-04T15:45:18.551340+00:00',
        'mru_id': 1,
        'name': 'alloy',
        'order': 0
    }


def test_uac_status_plugin_software(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = UACStatusPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        'consent_prompt_admin': 5,
        'consent_prompt_user': 3,
        'enable_limited_user_accounts': 1,
        'enable_virtualization': 1,
        'filter_admin_token': 0,
        'last_write': '2011-08-30T18:47:10.734144+00:00'
    }


def test_last_logon_plugin_software(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = LastLogonPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        'last_logged_on_provider': '{6F45DC1E-5384-457A-BC13-2CD81B0D28ED}',
        'last_logged_on_sam_user': 'SHIELDBASE\\rsydow',
        'last_logged_on_user': 'SHIELDBASE\\rsydow',
        'last_write': '2012-04-04T12:20:41.453654+00:00',
        'show_tablet_keyboard': 0
    }


def test_typed_urls_plugin_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    plugin_instance = TypedUrlsPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        'last_write': '2012-04-03T22:37:55.411500+00:00',
        'entries': [
            {'url1': 'http://199.73.28.114:53/'},
            {'url2': 'http://go.microsoft.com/fwlink/?LinkId=69157'}
        ]
    }
