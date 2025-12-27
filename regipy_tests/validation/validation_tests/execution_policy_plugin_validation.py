from regipy.plugins.software.execpolicy import ExecutionPolicyPlugin
from regipy_tests.validation.validation import ValidationCase


class ExecutionPolicyPluginValidationCase(ValidationCase):
    plugin = ExecutionPolicyPlugin
    test_hive_file_name = "SOFTWARE.xz"

    expected_entries = [
        {
            "type": "powershell",
            "key_path": "\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell",
            "last_write": "2010-11-10T18:09:15.781250+00:00",
            "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
        {
            "type": "wsh",
            "key_path": "\\Microsoft\\Windows Script Host\\Settings",
            "last_write": "2009-07-14T04:37:08.306366+00:00",
            "display_logo": False,
        },
    ]
    expected_entries_count = 2
