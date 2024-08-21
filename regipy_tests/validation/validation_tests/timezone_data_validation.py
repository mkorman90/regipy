
from regipy.plugins.system.timezone_data import TimezoneDataPlugin
from regipy_tests.validation.validation import ValidationCase


class TimezoneDataPluginValidationCase(ValidationCase):
    plugin = TimezoneDataPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            