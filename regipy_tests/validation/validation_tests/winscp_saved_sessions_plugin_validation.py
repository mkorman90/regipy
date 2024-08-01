from regipy.plugins.ntuser.winscp_saved_sessions import WinSCPSavedSessionsPlugin
from regipy_tests.validation.validation import ValidationCase


class WinSCPSavedSessionsPluginValidationCase(ValidationCase):
    plugin = WinSCPSavedSessionsPlugin
    test_hive_file_name = "ntuser_hive_2.xz"
    expected_entries_count = 2
