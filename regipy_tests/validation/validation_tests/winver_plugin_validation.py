
from regipy.plugins.software.winver import WinVersionPlugin
from regipy_tests.validation.validation import ValidationCase


class WinVersionPluginValidationCase(ValidationCase):
    plugin = WinVersionPlugin
    test_hive_file_name = "software.xz"
    exact_expected_result = None

            