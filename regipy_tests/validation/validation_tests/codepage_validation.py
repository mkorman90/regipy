
from regipy.plugins.system.codepage import CodepagePlugin
from regipy_tests.validation.validation import ValidationCase


class CodepagePluginValidationCase(ValidationCase):
    plugin = CodepagePlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            