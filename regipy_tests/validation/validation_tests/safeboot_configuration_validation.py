
from regipy.plugins.system.safeboot_configuration import SafeBootConfigurationPlugin
from regipy_tests.validation.validation import ValidationCase


class SafeBootConfigurationPluginValidationCase(ValidationCase):
    plugin = SafeBootConfigurationPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            