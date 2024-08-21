
from regipy.plugins.system.disablelastaccess import DisableLastAccessPlugin
from regipy_tests.validation.validation import ValidationCase


class DisableLastAccessPluginValidationCase(ValidationCase):
    plugin = DisableLastAccessPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            