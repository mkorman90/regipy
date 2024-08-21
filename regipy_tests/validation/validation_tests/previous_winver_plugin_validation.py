
from regipy.plugins.system.previous_winver import PreviousWinVersionPlugin
from regipy_tests.validation.validation import ValidationCase


class PreviousWinVersionPluginValidationCase(ValidationCase):
    plugin = PreviousWinVersionPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            