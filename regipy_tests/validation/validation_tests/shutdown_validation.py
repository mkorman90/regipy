
from regipy.plugins.system.shutdown import ShutdownPlugin
from regipy_tests.validation.validation import ValidationCase


class ShutdownPluginValidationCase(ValidationCase):
    plugin = ShutdownPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            