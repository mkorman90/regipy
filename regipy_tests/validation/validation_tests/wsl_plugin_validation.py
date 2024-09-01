from regipy.plugins.ntuser.wsl import WSLPlugin
from regipy_tests.validation.validation import ValidationCase


class WSLPluginValidationCase(ValidationCase):
    plugin = WSLPlugin
    test_hive_file_name = ""
    exact_expected_result = {}
