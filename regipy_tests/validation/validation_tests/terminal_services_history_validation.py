
from regipy.plugins.ntuser.tsclient import TSClientPlugin
from regipy_tests.validation.validation import ValidationCase


class TSClientPluginValidationCase(ValidationCase):
    plugin = TSClientPlugin
    test_hive_file_name = "ntuser.xz"
    exact_expected_result = None

            