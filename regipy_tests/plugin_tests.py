import pytest
import datetime as dt
from regipy.plugins import (
    NTUserPersistencePlugin,
    UserAssistPlugin,
    AmCachePlugin,
    WordWheelQueryPlugin,
    UACStatusPlugin,
    LastLogonPlugin,
    SoftwareClassesInstallerPlugin,
    InstalledProgramsSoftwarePlugin,
    RASTracingPlugin,
    PrintDemonPlugin,
    ServicesPlugin,
    NtuserClassesInstallerPlugin,
)
from regipy.registry import RegistryHive
from regipy.plugins.ntuser.typed_urls import TypedUrlsPlugin
from regipy.plugins.ntuser.typed_paths import TypedPathsPlugin
from regipy.plugins.software.profilelist import ProfileListPlugin
from regipy.plugins.software.persistence import SoftwarePersistencePlugin
from regipy.plugins.system.computer_name import ComputerNamePlugin
from regipy.plugins.system.shimcache import ShimCachePlugin
from regipy.plugins.system.bootkey import BootKeyPlugin
from regipy.plugins.system.host_domain_name import HostDomainNamePlugin
from regipy.plugins.sam.local_sid import LocalSidPlugin
from regipy.plugins.security.domain_sid import DomainSidPlugin
from regipy.plugins.bcd.boot_entry_list import BootEntryListPlugin
from regipy.plugins.system.wdigest import WDIGESTPlugin
from regipy.plugins.system.usbstor import USBSTORPlugin
from regipy.plugins.ntuser.winrar import WinRARPlugin
from regipy.plugins.ntuser.network_drives import NetworkDrivesPlugin
from regipy.plugins.ntuser.shellbags_ntuser import ShellBagNtuserPlugin
from regipy.plugins.ntuser.winscp_saved_sessions import WinSCPSavedSessionsPlugin
from regipy.plugins.system.network_data import NetworkDataPlugin
from regipy.plugins.usrclass.shellbags_usrclass import ShellBagUsrclassPlugin
from regipy.plugins.software.winver import WinVersionPlugin
from regipy.plugins.system.previous_winver import PreviousWinVersionPlugin
from regipy.plugins.system.shutdown import ShutdownPlugin
from regipy.plugins.system.processor_architecture import ProcessorArchitecturePlugin
from regipy.plugins.system.crash_dump import CrashDumpPlugin
from regipy.plugins.software.susclient import SusclientPlugin
from regipy.plugins.system.disablelastaccess import DisableLastAccessPlugin
from regipy.plugins.system.codepage import CodepagePlugin
from regipy.plugins.software.disablesr import DisableSRPlugin
from regipy.plugins.system.diag_sr import DiagSRPlugin
from regipy.plugins.software.spp_clients import SppClientsPlugin
from regipy.plugins.system.backuprestore import BackupRestorePlugin
from regipy.plugins.system.timezone_data2 import TimezoneDataPlugin2
from regipy.plugins.system.bam import BAMPlugin

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

    assert len(plugin_instance.entries) == 1367
    assert plugin_instance.entries[100] == {
        'full_path': 'C:\\Windows\\system32\\TPVMMondeu.dll',
        'last_modified_timestamp_2': '2017-03-17T05:06:04.002722+00:00',
        'program_id': '75a010066bb612ca7357ce31df8e9f0300000904',
        'sha1': '056f4b9d9ec9b5dc548e1b460da889e44089d76f',
        'timestamp': '2017-08-03T11:34:02.263418+00:00'
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


def test_classes_installer_plugin_ntuser(ntuser_hive_2):
    registry_hive = RegistryHive(ntuser_hive_2)
    plugin_instance = NtuserClassesInstallerPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries[0] == {
        'identifier': '8A4152964845CF540BEAEBD27F7A8519', 
        'timestamp': '2022-02-15T07:00:07.245646+00:00', 
        'product_name': 'Microsoft Visual C++ Compiler Package for Python 2.7', 
        'is_hidden': False
    }

    assert not any([x['is_hidden'] for x in plugin_instance.entries])


def test_ras_tracing_plugin_software(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = RASTracingPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert len(plugin_instance.entries) == 70

    assert plugin_instance.entries[0] == {
        "key": "\\Microsoft\\Tracing",
        "name": "AcroRd32_RASAPI32",
        "timestamp": "2012-03-16T21:31:26.613878+00:00",
    }

    assert plugin_instance.entries[-1] == {
        "key": "\\Microsoft\\Tracing",
        "name": "wmplayer_RASMANCS",
        "timestamp": "2012-03-12T20:58:55.476336+00:00",
    }


def test_installed_programs_plugin_software(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = InstalledProgramsSoftwarePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert len(plugin_instance.entries) == 67

    assert plugin_instance.entries[0] == {
        "registry_path": "\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "service_name": "AddressBook",
        "timestamp": "2009-07-14T04:41:12.758808+00:00",
    }

    assert (
        plugin_instance.entries[-1].items()
        > {
            "service_name": "{FE2F6A2C-196E-4210-9C04-2B1BC21F07EF}",
            "timestamp": "2011-07-05T22:58:57.996094+00:00",
            "registry_path": "\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            "UninstallString": "MsiExec.exe /X{FE2F6A2C-196E-4210-9C04-2B1BC21F07EF}",
            "URLInfoAbout": "http://www.vmware.com",
            "DisplayName": "VMware Tools",
        }.items()
    )


def test_last_logon_plugin_software(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = LastLogonPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        "last_logged_on_provider": "{6F45DC1E-5384-457A-BC13-2CD81B0D28ED}",
        "last_logged_on_sam_user": "SHIELDBASE\\rsydow",
        "last_logged_on_user": "SHIELDBASE\\rsydow",
        "last_write": "2012-04-04T12:20:41.453654+00:00",
        "show_tablet_keyboard": 0,
    }


def test_typed_urls_plugin_ntuser(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    plugin_instance = TypedUrlsPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        "last_write": "2012-04-03T22:37:55.411500+00:00",
        "entries": [
            {"url1": "http://199.73.28.114:53/"},
            {"url2": "http://go.microsoft.com/fwlink/?LinkId=69157"},
        ],
    }


def test_profilelist_plugin(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = ProfileListPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "last_write": "2009-07-14T04:41:12.493608+00:00",
            "path": "%systemroot%\\system32\\config\\systemprofile",
            "flags": 12,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-18",
            "load_time": None,
            "local_load_time": None,
        },
        {
            "last_write": "2010-11-10T18:09:16.250000+00:00",
            "path": "C:\\Windows\\ServiceProfiles\\LocalService",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-19",
            "load_time": None,
            "local_load_time": None,
        },
        {
            "last_write": "2010-11-10T18:09:16.250000+00:00",
            "path": "C:\\Windows\\ServiceProfiles\\NetworkService",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-20",
            "load_time": None,
            "local_load_time": None,
        },
        {
            "last_write": "2010-11-10T17:22:52.109376+00:00",
            "path": "C:\\Users\\Pepper",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-21-100689374-1717798114-2601648136-1000",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
        {
            "last_write": "2012-04-04T12:42:17.719834+00:00",
            "path": "C:\\Users\\SRL-Helpdesk",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-21-100689374-1717798114-2601648136-1001",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
        {
            "last_write": "2011-08-21T00:51:19.820166+00:00",
            "path": "C:\\Users\\nfury",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-21-2036804247-3058324640-2116585241-1105",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
        {
            "last_write": "2011-08-23T01:33:29.006350+00:00",
            "path": "C:\\Users\\mhill",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-21-2036804247-3058324640-2116585241-1106",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
        {
            "last_write": "2011-09-17T13:33:17.372366+00:00",
            "path": "C:\\Users\\Tdungan",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-21-2036804247-3058324640-2116585241-1107",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
        {
            "last_write": "2012-04-06T19:44:17.844274+00:00",
            "path": "C:\\Users\\nromanoff",
            "flags": 0,
            "full_profile": None,
            "state": 0,
            "sid": "S-1-5-21-2036804247-3058324640-2116585241-1109",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
        {
            "last_write": "2012-04-06T19:42:31.408714+00:00",
            "path": "C:\\Users\\rsydow",
            "flags": 0,
            "full_profile": None,
            "state": 256,
            "sid": "S-1-5-21-2036804247-3058324640-2116585241-1114",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
        {
            "last_write": "2012-04-06T19:22:20.845938+00:00",
            "path": "C:\\Users\\vibranium",
            "flags": 0,
            "full_profile": None,
            "state": 256,
            "sid": "S-1-5-21-2036804247-3058324640-2116585241-1673",
            "load_time": "1601-01-01T00:00:00+00:00",
            "local_load_time": None,
        },
    ]


def test_printdemon_plugin(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = PrintDemonPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM1:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM2:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM3:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": ["9600", "n", "8", "1"],
            "port_name": "COM4:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "FILE:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "LPT1:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "LPT2:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "LPT3:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "XPSPort:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "Ne00:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "Ne01:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
        {
            "parameters": 0,
            "port_name": "nul:",
            "timestamp": "2010-11-10T10:35:02.448040+00:00",
        },
    ]


def test_services_plugin_on_corrupted_hive(corrupted_system_hive):
    registry_hive = RegistryHive(corrupted_system_hive)
    plugin_instance = ServicesPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries["\\ControlSet001\\Services"]["services"][0] == {
        "last_modified": "2008-10-21T17:48:29.328124+00:00",
        "name": "Abiosdsk",
        "parameters": [],
        "values": [
            {
                "is_corrupted": False,
                "name": "ErrorControl",
                "value": 0,
                "value_type": "REG_DWORD",
            },
            {
                "is_corrupted": False,
                "name": "Group",
                "value": "Primary disk",
                "value_type": "REG_SZ",
            },
            {
                "is_corrupted": False,
                "name": "Start",
                "value": 4,
                "value_type": "REG_DWORD",
            },
            {
                "is_corrupted": False,
                "name": "Tag",
                "value": 3,
                "value_type": "REG_DWORD",
            },
            {
                "is_corrupted": False,
                "name": "Type",
                "value": 1,
                "value_type": "REG_DWORD",
            },
        ],
    }


def test_local_sid_plugin_sam(sam_hive):
    registry_hive = RegistryHive(sam_hive)
    plugin_instance = LocalSidPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "machine_sid": "S-1-5-21-1760460187-1592185332-161725925",
            "timestamp": "2014-09-24T03:36:43.549302+00:00",
        }
    ]


def test_bootkey_plugin_system(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = BootKeyPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "key": "e7f28d88f470cfed67dbcdb62ed1275b",
            "timestamp": "2012-04-04T11:47:46.203124+00:00",
        },
        {
            "key": "e7f28d88f470cfed67dbcdb62ed1275b",
            "timestamp": "2012-04-04T11:47:46.203124+00:00",
        },
    ]


def test_host_domain_name_plugin_system(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = HostDomainNamePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "hostname": "WKS-WIN732BITA",
            "domain": "shieldbase.local",
            "timestamp": "2011-09-17T13:43:23.770078+00:00",
        },
        {
            "hostname": "WKS-WIN732BITA",
            "domain": "shieldbase.local",
            "timestamp": "2011-09-17T13:43:23.770078+00:00",
        },
    ]


def test_domain_sid_plugin_security(security_hive):
    registry_hive = RegistryHive(security_hive)
    plugin_instance = DomainSidPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "domain_name": "WORKGROUP",
            "domain_sid": None,
            "machine_sid": None,
            "timestamp": "2021-08-05T10:43:08.911000+00:00",
        }
    ]


def test_boot_entry_list_plugin_bcd(bcd_hive):
    registry_hive = RegistryHive(bcd_hive)
    plugin_instance = BootEntryListPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "guid": "{733b62de-f608-11eb-825c-c112f60133ab}",
            "type": "0x101FFFFF",
            "name": "Linux Boot Manager",
            "gpt_disk": "376e5397-7d1f-4e4f-a668-5a62c1269e60",
            "gpt_partition": "24e0e103-9bc2-477e-a5e2-3e42d2bb134f",
            "image_path": "\\EFI\\systemd\\systemd-bootx64.efi",
            "timestamp": "2021-08-09T02:13:30.992594+00:00",
        },
        {
            "guid": "{733b62e2-f608-11eb-825c-c112f60133ab}",
            "type": "0x101FFFFF",
            "name": "UEFI OS",
            "gpt_disk": "376e5397-7d1f-4e4f-a668-5a62c1269e60",
            "gpt_partition": "24e0e103-9bc2-477e-a5e2-3e42d2bb134f",
            "image_path": "\\EFI\\BOOT\\BOOTX64.EFI",
            "timestamp": "2021-08-09T02:13:30.992594+00:00",
        },
        {
            "guid": "{733b62e3-f608-11eb-825c-c112f60133ab}",
            "type": "0x101FFFFF",
            "name": "Windows Boot Manager",
            "gpt_disk": "376e5397-7d1f-4e4f-a668-5a62c1269e60",
            "gpt_partition": "24e0e103-9bc2-477e-a5e2-3e42d2bb134f",
            "image_path": "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            "timestamp": "2021-08-09T02:13:30.992594+00:00",
        },
        {
            "guid": "{733b62e4-f608-11eb-825c-c112f60133ab}",
            "type": "0x10200004",
            "name": "Windows Resume Application",
            "gpt_disk": "0b2394a9-095e-487d-8d48-719ecd4d78ca",
            "gpt_partition": "8e0f2c38-e4ea-47ba-b7fc-9d8c74dccf0b",
            "image_path": "\\Windows\\system32\\winresume.efi",
            "timestamp": "2021-08-09T02:13:30.992594+00:00",
        },
        {
            "guid": "{733b62e5-f608-11eb-825c-c112f60133ab}",
            "type": "0x10200003",
            "name": "Windows 10",
            "gpt_disk": "0b2394a9-095e-487d-8d48-719ecd4d78ca",
            "gpt_partition": "8e0f2c38-e4ea-47ba-b7fc-9d8c74dccf0b",
            "image_path": "\\Windows\\system32\\winload.efi",
            "timestamp": "2021-08-09T02:13:30.992594+00:00",
        },
        {
            "guid": "{733b62e6-f608-11eb-825c-c112f60133ab}",
            "type": "0x10200003",
            "name": "Windows Recovery Environment",
            "gpt_disk": "00000001-0090-0000-0500-000006000000",
            "gpt_partition": "00000003-0000-0000-0000-000000000000",
            "image_path": "\\windows\\system32\\winload.efi",
            "timestamp": "2021-08-09T02:13:30.976970+00:00",
        },
        {
            "guid": "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            "type": "0x10100002",
            "name": "Windows Boot Manager",
            "gpt_disk": "0b2394a9-095e-487d-8d48-719ecd4d78ca",
            "gpt_partition": "36be3955-63bf-4068-a6ab-00195cca3a22",
            "image_path": "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            "timestamp": "2021-08-09T02:13:30.992594+00:00",
        },
        {
            "guid": "{b2721d73-1db4-4c62-bf78-c548a880142d}",
            "type": "0x10200005",
            "name": "Windows Memory Diagnostic",
            "gpt_disk": "0b2394a9-095e-487d-8d48-719ecd4d78ca",
            "gpt_partition": "36be3955-63bf-4068-a6ab-00195cca3a22",
            "image_path": "\\EFI\\Microsoft\\Boot\\memtest.efi",
            "timestamp": "2021-08-09T02:13:30.976970+00:00",
        },
    ]


def test_wdigest(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = WDIGESTPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "subkey": r"\ControlSet001\Control\SecurityProviders\WDigest",
            "timestamp": "2009-07-14T04:37:09.491968+00:00",
            "use_logon_credential": 1,
        },
        {
            "subkey": r"\ControlSet002\Control\SecurityProviders\WDigest",
            "timestamp": "2009-07-14T04:37:09.491968+00:00",
            "use_logon_credential": None,
        },
    ]


def test_winrar(ntuser_hive):
    registry_hive = RegistryHive(ntuser_hive)
    plugin_instance = WinRARPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "last_write": "2021-11-18T13:59:04.888952+00:00",
            "file_path": "C:\\Users\\tony\\Downloads\\RegistryFinder64.zip",
            "operation": "archive_opened",
            "value_name": "0",
        },
        {
            "last_write": "2021-11-18T13:59:04.888952+00:00",
            "file_path": "C:\\temp\\token.zip",
            "operation": "archive_opened",
            "value_name": "1",
        },
        {
            "last_write": "2021-11-18T13:59:50.023788+00:00",
            "file_name": "Tools.zip",
            "operation": "archive_created",
            "value_name": "0",
        },
        {
            "last_write": "2021-11-18T13:59:50.023788+00:00",
            "file_name": "data.zip",
            "operation": "archive_created",
            "value_name": "1",
        },
        {
            "last_write": "2021-11-18T14:00:44.180468+00:00",
            "file_path": "C:\\Users\\tony\\Downloads",
            "operation": "archive_extracted",
            "value_name": "0",
        },
        {
            "last_write": "2021-11-18T14:00:44.180468+00:00",
            "file_path": "C:\\temp",
            "operation": "archive_extracted",
            "value_name": "1",
        },
    ]


def test_netdrives(ntuser_hive):

    registry_hive = RegistryHive(ntuser_hive)
    plugin_instance = NetworkDrivesPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == [
        {
            "drive_letter": r"p",
            "last_write": "2012-04-03T22:08:18.840132+00:00",
            "network_path": "\\\\controller\\public",
        }
    ]


def test_winscp_saved_sessions_plugin(ntuser_hive_2):
    registry_hive = RegistryHive(ntuser_hive_2)
    plugin_instance = WinSCPSavedSessionsPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert len(plugin_instance.entries) == 2

    assert plugin_instance.entries[1] == {
        "FSProtocol": 7,
        "Ftps": 1,
        "hive_name": "HKEY_CURRENT_USER",
        "HostName": "s3.amazonaws.com",
        "IsWorkspace": 1,
        "key_path": "HKEY_CURRENT_USER\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\personalab/0000",
        "LocalDirectory": "C:%5CUsers%5Ctony%5CDocuments",
        "PortNumber": 443,
        "RemoteDirectory": "/dev-personalab-velocityapp-data/uploads/Amnon/Lunar_Memdumps",
        "timestamp": "2022-04-25T09:53:58.125852+00:00",
        "UserName": "AKIAYTYA2O7PWLAQQOCU",
    }


def test_usbstor(system_hive_with_filetime):
    registry_hive = RegistryHive(system_hive_with_filetime)
    plugin_instance = USBSTORPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries[0] == {
        "device_name": "SanDisk Cruzer USB Device",
        "disk_guid": "{fc416b61-6437-11ea-bd0c-a483e7c21469}",
        "first_installed": "2020-03-17T14:02:38.955490+00:00",
        "key_path": "\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.20\\200608767007B7C08A6A&0",
        "last_connected": "2020-03-17T14:02:38.946628+00:00",
        "last_installed": "2020-03-17T14:02:38.955490+00:00",
        "last_removed": "2020-03-17T14:23:45.504690+00:00",
        "last_write": "2020-03-17T14:02:38.965050+00:00",
        "manufacturer": "Ven_SanDisk",
        "serial_number": "200608767007B7C08A6A&0",
        "title": "Prod_Cruzer",
        "version": "Rev_1.20",
    }


def test_typed_paths_plugin_ntuser(shellbags_ntuser):
    registry_hive = RegistryHive(shellbags_ntuser)
    plugin_instance = TypedPathsPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        "last_write": "2022-02-06T13:46:04.945080+00:00",
        "entries": [
            {"url1": "cmd"},
            {"url2": "C:\\Offline\\AD"},
            {"url3": "git"},
            {"url4": "powershell"},
            {"url5": "C:\\Program Files"},
            {"url6": "Network"},
            {"url7": "\\\\wsl$\\Ubuntu\\projects\\CAD316_001\\partition_p1"},
            {"url8": "\\\\wsl$\\Ubuntu\\projects"},
            {"url9": "\\\\wsl$\\Ubuntu"},
            {"url10": "C:\\Users\\tony\\Github"},
            {"url11": "C:\\Users\\tony\\Github\\velocity-client-master"},
            {"url12": "C:\\Users\\tony\\Github\\cogz"},
            {"url13": "C:\\Users\\tony\\Github\\cogz\\cogz"},
            {"url14": "Quick access"},
            {"url15": "C:\\ProgramData\\chocolatey\\lib\\yara\\tools"},
            {"url16": "C:\\Training\\MT01\\exercise"},
        ],
    }


def test_shellbags_plugin_ntuser(shellbags_ntuser):
    registry_hive = RegistryHive(shellbags_ntuser)
    plugin_instance = ShellBagNtuserPlugin(registry_hive, as_json=True)
    plugin_instance.run()
    assert plugin_instance.entries[-1] == {
        "value": "rekall",
        "slot": "0",
        "reg_path": "\\Software\\Microsoft\\Windows\\Shell\\BagMRU\\2\\0",
        "value_name": "0",
        "node_slot": "11",
        "shell_type": "Directory",
        "path": "Search Folder\\tmp\\rekall",
        "creation_time": dt.datetime(2021, 8, 16, 9, 41, 32).isoformat(),
        "full path": None,
        "access_time": dt.datetime(2021, 8, 16, 9, 43, 22).isoformat(),
        "modification_time": dt.datetime(2021, 8, 16, 9, 41, 32).isoformat(),
        "last_write": "2021-08-16T09:44:39.333110+00:00",
        "location description": None,
        "mru_order": "0",
        "mru_order_location": 0,
    }

    assert len(plugin_instance.entries) == 102


def test_shellbags_plugin_usrclass(transaction_usrclass):
    registry_hive = RegistryHive(transaction_usrclass)
    plugin_instance = ShellBagUsrclassPlugin(registry_hive, as_json=True)
    plugin_instance.run()
    assert plugin_instance.entries[-1] == {
        "value": "Dropbox",
        "slot": "9",
        "reg_path": "\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "value_name": "9",
        "node_slot": "20",
        "shell_type": "Root Folder",
        "path": "Dropbox",
        "creation_time": None,
        "full path": None,
        "access_time": None,
        "modification_time": None,
        "last_write": "2018-04-05T02:13:26.843024+00:00",
        "location description": None,
        "mru_order": "4-8-7-6-9-0-1-5-3-2",
        "mru_order_location": 4,
    }

    assert len(plugin_instance.entries) == 29


def test_network_data_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = NetworkDataPlugin(registry_hive, as_json=True)
    plugin_instance.run()
    
    assert plugin_instance.entries["\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces"]["interfaces"][0] == {
        "interface_name": "{698E50A9-4F58-4D86-B61D-F42E58DCACF6}",
        "last_modified": "2011-09-17T13:43:23.770078+00:00",
        "dhcp_enabled": False,
        "ip_address": ["10.3.58.5"],
        "subnet_mask": ["255.255.255.0"],
        "default_gateway": ["10.3.58.1"],
        "name_server": "10.3.58.4",
        "domain": 0,
    }


def test_win_version_plugin(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = WinVersionPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries['\\Microsoft\\Windows NT\\CurrentVersion'] == {
        "BuildLab": "7601.win7sp1_gdr.111118-2330",
        "BuildLabEx": "7601.17727.x86fre.win7sp1_gdr.111118-2330",
        "CSDVersion": "Service Pack 1",
        "CurrentBuild": "7601",
        "CurrentBuildNumber": "7601",
        "CurrentVersion": "6.1",
        "EditionID": "Ultimate",
        "InstallationType": "Client",
        "InstallDate": "2010-11-10 16:28:55",
        "last_write": "2012-03-14T07:09:21.562500+00:00",
        "ProductId": "00426-067-1817155-86250",
        "ProductName": "Windows 7 Ultimate",
        "RegisteredOrganization": 0,
        "RegisteredOwner": "Windows User"
    }   

def test_previous_win_version_plugin(system_hive_with_filetime):
    registry_hive = RegistryHive(system_hive_with_filetime)
    plugin_instance = PreviousWinVersionPlugin(registry_hive, as_json=True)
    plugin_instance.run()
    
    # work with SYSTEM_WIN_10_1709 HIVE
    assert plugin_instance.entries == [
        {
            "BuildLab": "15063.rs2_release.170317-1834",
            "BuildLabEx": "15063.0.amd64fre.rs2_release.170317-1834",
            "CompositionEditionID": "Professional",
            "CurrentBuild": "15063",
            "CurrentBuildNumber": "15063",
            "CurrentVersion": "6.3",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "InstallDate": "2017-07-12 07:18:28",
            "key": "\\Setup\\Source OS (Updated on 1/6/2019 02:18:37)",
            "ProductId": "00330-80111-62153-AA362",
            "ProductName": "Windows 10 Pro",
            "RegisteredOrganization": 0,
            "RegisteredOwner": "Windows User",
            "update_date": "2019-01-06 02:18:37"
        },
        {
            "BuildLab": "17134.rs4_release.180410-1804",
            "BuildLabEx": "17134.1.amd64fre.rs4_release.180410-1804",
            "CompositionEditionID": "Enterprise",
            "CurrentBuild": "17134",
            "CurrentBuildNumber": "17134",
            "CurrentVersion": "6.3",
            "EditionID": "Professional",
            "InstallationType": "Client",
            "InstallDate": "2019-01-27 10:39:32",
            "key": "\\Setup\\Source OS (Updated on 5/16/2019 00:55:20)",
            "ProductId": "00330-80111-62153-AA442",
            "ProductName": "Windows 10 Pro",
            "RegisteredOrganization": 0,
            "RegisteredOwner": "Windows User",
            "update_date": "2019-05-16 00:55:20"
        }
    ]

def test_shutdown_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = ShutdownPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        "\\ControlSet001\\Control\\Windows": {
            "date": "2012-04-04 01:58:40",
            "last_write": "2012-04-04T01:58:40.839250+00:00"
        },
        "\\ControlSet002\\Control\\Windows": {
            "date": "2012-04-04 01:58:40",
            "last_write": "2012-04-04T01:58:40.839250+00:00"
        }
    }

def test_processor_architecture_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = ProcessorArchitecturePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries['\\ControlSet001\\Control\\Session Manager\\Environment'] == {
        "NUMBER_OF_PROCESSORS": 49,
        "PROCESSOR_ARCHITECTURE": "x86",
        "PROCESSOR_IDENTIFIER": "x86 Family 16 Model 8 Stepping 0, AuthenticAMD",
        "PROCESSOR_REVISION": "0800"
    }
    
def test_crash_dump_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = CrashDumpPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries['\\ControlSet001\\Control\\CrashControl'] == {
        "CrashDumpEnabled": 2,
        "CrashDumpEnabledStr": "Kernel memory dump",
        "DumpFile": "%SystemRoot%\\MEMORY.DMP",
        "last_write": "2012-04-04T11:47:36.984376+00:00",
        "LogEvent": 1,
        "MinidumpDir": "%SystemRoot%\\Minidump"
    }
    
def test_susclient_plugin(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = SusclientPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries['\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate'] == {
        "last_write": "2012-03-14T07:05:41.719626+00:00",
        "LastRestorePointSetTime": "2012-03-14 07:05:41",
        "SusClientId": "50df98f2-964a-496d-976d-d95296e13929",
        "SusClientIdValidation": ""
    }
    
def test_disable_last_access_plugin(system_hive_with_filetime):
    registry_hive = RegistryHive(system_hive_with_filetime)
    plugin_instance = DisableLastAccessPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    # work with SYSTEM_WIN_10_1709 HIVE
    assert plugin_instance.entries['\\ControlSet001\\Control\\FileSystem'] == {
        "last_write": "2020-02-13T11:59:20.987114+00:00",
        "NtfsDisableLastAccessUpdate": "80000003",
        "NtfsDisableLastAccessUpdateStr": "(System Managed, Updates Disabled)"
    }
    
def test_code_page_plugin(system_hive_with_filetime):
    registry_hive = RegistryHive(system_hive_with_filetime)
    plugin_instance = CodepagePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    # work with SYSTEM_WIN_10_1709 HIVE
    assert plugin_instance.entries['\\ControlSet001\\Control\\Nls\\CodePage'] == {
        "ACP": "1252",
        "last_write": "2019-05-16T08:22:00.160628+00:00"
    }
    
def test_disable_sr_plugin(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = DisableSRPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        "\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore": {
            "last_write": "2012-03-31T04:00:23.006648+00:00"
        }
    }
    
def test_diag_sr_plugin(system_hive):
    registry_hive = RegistryHive(system_hive)
    plugin_instance = DiagSRPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries['\\ControlSet001\\Services\\VSS\\Diag\\SystemRestore'] == {
        "last_write": "2012-03-31T04:00:22.998834+00:00",
        "SrCreateRp (Enter)": "2012-03-31 04:00:01",
        "SrCreateRp (Leave)": "2012-03-31 04:00:22"
    }
    
def test_spp_clients_plugin(software_hive):
    registry_hive = RegistryHive(software_hive)
    plugin_instance = SppClientsPlugin(registry_hive, as_json=True)
    plugin_instance.run()

    assert plugin_instance.entries == {
        "\\Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients": {
            "{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}": [
                "\\\\?\\Volume{656b1715-ecf6-11df-92e6-806e6f6e6963}\\:(C:)"
            ],
            "last_write": "2012-03-15T22:32:18.089574+00:00"
        }
    }
    
def test_backup_restore_plugin(system_hive_with_filetime):
    registry_hive = RegistryHive(system_hive_with_filetime)
    plugin_instance = BackupRestorePlugin(registry_hive, as_json=True)
    plugin_instance.run()

    # work with SYSTEM_WIN_10_1709 HIVE
    assert plugin_instance.entries == {
        "\\ControlSet001\\Control\\BackupRestore\\FilesNotToBackup": {
            "BITS_metadata": [
                "%ProgramData%\\Microsoft\\Network\\Downloader\\* /s"
            ],
            "ETW": [
                "%SystemRoot%\\system32\\LogFiles\\WMI\\RtBackup\\*.*"
            ],
            "FVE_Control": [
                "\\System Volume Information\\FVE.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.*"
            ],
            "FVE_Log": [
                "\\System Volume Information\\FVE.{c9ca54a3-6983-46b7-8684-a7e5e23499e3}"
            ],
            "FVE_Wipe": [
                "\\System Volume Information\\FVE.{9ef82dfa-1239-4a30-83e6-3b3e9b8fed08}"
            ],
            "FVE2_Control": [
                "\\System Volume Information\\FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.*"
            ],
            "FVE2_Log": [
                "\\System Volume Information\\FVE2.{c9ca54a3-6983-46b7-8684-a7e5e23499e3}"
            ],
            "FVE2_VBB": [
                "\\System Volume Information\\FVE2.{24e6f0ae-6a00-4f73-984b-75ce9942852d}"
            ],
            "FVE2_Wipe": [
                "\\System Volume Information\\FVE2.{9ef82dfa-1239-4a30-83e6-3b3e9b8fed08}"
            ],
            "FVE2_WipeInfo": [
                "\\System Volume Information\\FVE2.{aff97bac-a69b-45da-aba1-2cfbce434750}.*"
            ],
            "FVE2_WipeX": [
                "\\System Volume Information\\FVE2.{9ef82dfa-1239-4a30-83e6-3b3e9b8fed08}.*"
            ],
            "Internet Explorer": [
                "%UserProfile%\\index.dat /s"
            ],
            "Kernel Dumps": [
                "%systemroot%\\Minidump\\* /s",
                "%systemroot%\\memory.dmp"
            ],
            "last_write": "2019-05-16T08:21:59.973146+00:00",
            "Memory Page File": [
                "\\Pagefile.sys"
            ],
            "Mount Manager": [
                "\\System Volume Information\\MountPointManagerRemoteDatabase"
            ],
            "MS Distributed Transaction Coordinator": [
                "C:\\Windows\\system32\\MSDtc\\MSDTC.LOG",
                "C:\\Windows\\system32\\MSDtc\\trace\\dtctrace.log"
            ],
            "Netlogon": [
                "%SystemRoot%\\netlogon.chg"
            ],
            "Power Management": [
                "\\hiberfil.sys"
            ],
            "Storage Tiers Management": [
                "\\System Volume Information\\Heat\\*.* /s"
            ],
            "Temporary Files": [
                "%TEMP%\\* /s"
            ],
            "VSS Default Provider": [
                "\\System Volume Information\\*{3808876B-C176-4e48-B7AE-04046E6CC752} /s"
            ],
            "VSS Service Alternate DB": [
                "\\System Volume Information\\*.{7cc467ef-6865-4831-853f-2a4817fd1bca}ALT"
            ],
            "VSS Service DB": [
                "\\System Volume Information\\*.{7cc467ef-6865-4831-853f-2a4817fd1bca}DB"
            ],
            "WER": [
                "%ProgramData%\\Microsoft\\Windows\\WER\\* /s"
            ],
            "WUA": [
                "%windir%\\softwaredistribution\\*.* /s"
            ]
        },
        "\\ControlSet001\\Control\\BackupRestore\\FilesNotToSnapshot": {
            "FVE": [
                "$AllVolumes$\\System Volume Information\\FVE.{9ef82dfa-1239-4a30-83e6-3b3e9b8fed08}"
            ],
            "FVE2_Wipe": [
                "$AllVolumes$\\System Volume Information\\FVE2.{9ef82dfa-1239-4a30-83e6-3b3e9b8fed08}"
            ],
            "FVE2_WipeX": [
                "$AllVolumes$\\System Volume Information\\FVE2.{9ef82dfa-1239-4a30-83e6-3b3e9b8fed08}.*"
            ],
            "last_write": "2020-02-13T08:47:50.455600+00:00",
            "ModernOutlookOAB": [
                "$UserProfile$\\AppData\\Local\\Packages\\Microsoft.Office.Desktop_8wekyb3d8bbwe\\LocalCache\\Local\\Microsoft\\Outlook\\*.oab /s"
            ],
            "ModernOutlookOST": [
                "$UserProfile$\\AppData\\Local\\Packages\\Microsoft.Office.Desktop_8wekyb3d8bbwe\\LocalCache\\Local\\Microsoft\\Outlook\\*.ost /s"
            ],
            "OutlookOST": [
                "$UserProfile$\\AppData\\Local\\Microsoft\\Outlook\\*.ost"
            ],
            "Storage Tiers Management": [
                "\\System Volume Information\\Heat\\*.* /s"
            ],
            "TSBACKUP": [
                "C:\\ProgramData\\FLEXnet\\*.* /s"
            ],
            "WUA": [
                "%windir%\\softwaredistribution\\*.* /s"
            ]
        },
        "\\ControlSet001\\Control\\BackupRestore\\KeysNotToRestore": {
            "last_write": "2019-05-16T08:21:59.973146+00:00",
            "Mount Manager": [
                "MountedDevices\\"
            ],
            "MS Distributed Transaction Coordinator": [
                "CurrentControlSet\\Control\\MSDTC\\ASR\\"
            ],
            "Pending Rename Operations": [
                "CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations"
            ],
            "Pending Rename Operations2": [
                "CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations2"
            ],
            "Session Manager": [
                "CurrentControlSet\\Control\\Session Manager\\AllowProtectedRenames"
            ]
        }
    }
    
def test_timezone_data2_plugin(system_hive_with_filetime):
    registry_hive = RegistryHive(system_hive_with_filetime)
    plugin_instance = TimezoneDataPlugin2(registry_hive, as_json=True)
    plugin_instance.run()

    # work with SYSTEM_WIN_10_1709 HIVE
    assert plugin_instance.entries['\\ControlSet001\\Control\\TimeZoneInformation'] == {
        "ActiveTimeBias": 420,
        "Bias": 480,
        "DaylightBias": -60,
        "DaylightName": "@tzres.dll,-211",
        "DaylightStart": "00000300020002000000000000000000",
        "DynamicDaylightTimeDisabled": 0,
        "last_write": "2020-03-09T13:07:51.297306+00:00",
        "StandardBias": 0,
        "StandardName": "@tzres.dll,-212",
        "StandardStart": "00000b00010002000000000000000000",
        "TimeZoneKeyName": "Pacific Standard Time"
    }
    