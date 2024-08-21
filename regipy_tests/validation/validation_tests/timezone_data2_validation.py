
from regipy.plugins.system.timezone_data2 import TimezoneDataPlugin2
from regipy_tests.validation.validation import ValidationCase


class TimezoneDataPlugin2ValidationCase(ValidationCase):
    plugin = TimezoneDataPlugin2
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            