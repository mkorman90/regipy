from regipy.plugins.software.disablesr import DisableSRPlugin
from regipy_tests.validation.validation import ValidationCase


class DisableSRPluginValidationCase(ValidationCase):
    plugin = DisableSRPlugin
    test_hive_file_name = "SOFTWARE.xz"
    exact_expected_result = {
        "\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore": {"last_write": "2012-03-31T04:00:23.006648+00:00"}
    }
