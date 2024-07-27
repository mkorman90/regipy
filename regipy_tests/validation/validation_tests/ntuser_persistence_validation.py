from regipy.plugins.ntuser.persistence import NTUserPersistencePlugin
from regipy_tests.validation.validation import ValidationCase


class NTUserPersistenceValidationCase(ValidationCase):
    plugin = NTUserPersistencePlugin
    test_hive_file_name = "NTUSER.DAT.xz"

    exact_expected_result = {"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": {
            "timestamp": "2012-04-03T21:19:54.837716+00:00",
            "values": [
                {
                    "name": "Sidebar",
                    "value_type": "REG_EXPAND_SZ",
                    "value": "%ProgramFiles%\\Windows Sidebar\\Sidebar.exe /autoRun",
                    "is_corrupted": False,
                }
            ],
        }
    }
    expected_entries_count = 1
