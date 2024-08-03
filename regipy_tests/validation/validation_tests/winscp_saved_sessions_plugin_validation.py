from regipy.plugins.ntuser.winscp_saved_sessions import WinSCPSavedSessionsPlugin
from regipy_tests.validation.validation import ValidationCase


class WinSCPSavedSessionsPluginValidationCase(ValidationCase):
    plugin = WinSCPSavedSessionsPlugin
    test_hive_file_name = "NTUSER_with_winscp.DAT.xz"
    expected_entries_count = 2
    expected_entries = [
        {
            "timestamp": "2022-04-25T09:53:58.125852+00:00",
            "hive_name": "HKEY_CURRENT_USER",
            "key_path": "HKEY_CURRENT_USER\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\\Default%20Settings",
        }
    ]
