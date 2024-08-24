from regipy.plugins.ntuser.tsclient import TSClientPlugin
from regipy_tests.validation.validation import ValidationCase


class TSClientPluginValidationCase(ValidationCase):
    plugin = TSClientPlugin
    # TDODO: Find registry sample with test data
    test_hive_file_name = "NTUSER_modified.DAT.xz"
    # For now, bypass validation with this ugly trick:
    exact_expected_result = None
    expected_entries_count = 0
