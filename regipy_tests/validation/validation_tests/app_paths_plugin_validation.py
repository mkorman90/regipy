from regipy.plugins.software.apppaths import AppPathsPlugin
from regipy_tests.validation.validation import ValidationCase


class AppPathsPluginValidationCase(ValidationCase):
    plugin = AppPathsPlugin
    test_hive_file_name = "SOFTWARE.xz"

    expected_entries = [
        {
            "key_path": "\\Microsoft\\Windows\\CurrentVersion\\App Paths\\AcroRd32.exe",
            "application": "AcroRd32.exe",
            "architecture": "x64",
            "last_write": "2011-08-28T22:41:26.262844+00:00",
            "path": "C:\\Program Files\\Adobe\\Reader 10.0\\Reader\\AcroRd32.exe",
            "app_path": "C:\\Program Files\\Adobe\\Reader 10.0\\Reader\\",
        }
    ]
    expected_entries_count = 34
