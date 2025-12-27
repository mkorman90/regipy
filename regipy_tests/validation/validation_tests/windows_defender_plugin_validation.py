from regipy.plugins.software.defender import WindowsDefenderPlugin
from regipy_tests.validation.validation import ValidationCase


class WindowsDefenderPluginValidationCase(ValidationCase):
    plugin = WindowsDefenderPlugin
    test_hive_file_name = "SOFTWARE.xz"

    exact_expected_result = [
        {
            "type": "configuration",
            "key_path": "\\Microsoft\\Windows Defender",
            "last_write": "2011-09-16T20:48:31.741870+00:00",
            "antispyware_disabled": True,
            "product_status": 0,
        }
    ]
