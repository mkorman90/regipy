from regipy.plugins.software.persistence import SoftwarePersistencePlugin
from regipy_tests.validation.validation import ValidationCase


class SoftwarePersistenceValidationCase(ValidationCase):
    plugin = SoftwarePersistencePlugin
    test_hive_file_name = "SOFTWARE.xz"

    exact_expected_result = {
        "\\Microsoft\\Windows\\CurrentVersion\\Run": {
            "timestamp": "2012-04-04T01:54:23.669836+00:00",
            "values": [
                {
                    "name": "VMware Tools",
                    "value_type": "REG_SZ",
                    "value": '"C:\\Program Files\\VMware\\VMware Tools\\VMwareTray.exe"',
                    "is_corrupted": False,
                },
                {
                    "name": "VMware User Process",
                    "value_type": "REG_SZ",
                    "value": '"C:\\Program Files\\VMware\\VMware Tools\\VMwareUser.exe"',
                    "is_corrupted": False,
                },
                {
                    "name": "Adobe ARM",
                    "value_type": "REG_SZ",
                    "value": '"C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\AdobeARM.exe"',
                    "is_corrupted": False,
                },
                {
                    "name": "McAfeeUpdaterUI",
                    "value_type": "REG_SZ",
                    "value": '"C:\\Program Files\\McAfee\\Common Framework\\udaterui.exe" /StartedFromRunKey',
                    "is_corrupted": False,
                },
                {
                    "name": "ShStatEXE",
                    "value_type": "REG_SZ",
                    "value": '"C:\\Program Files\\McAfee\\VirusScan Enterprise\\SHSTAT.EXE" /STANDALONE',
                    "is_corrupted": False,
                },
                {
                    "name": "McAfee Host Intrusion Prevention Tray",
                    "value_type": "REG_SZ",
                    "value": '"C:\\Program Files\\McAfee\\Host Intrusion Prevention\\FireTray.exe"',
                    "is_corrupted": False,
                },
                {
                    "name": "svchost",
                    "value_type": "REG_SZ",
                    "value": "c:\\windows\\system32\\dllhost\\svchost.exe",
                    "is_corrupted": False,
                },
            ],
        }
    }

    expected_entries_count = 1
