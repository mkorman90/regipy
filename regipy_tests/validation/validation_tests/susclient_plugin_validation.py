
from regipy.plugins.software.susclient import SusclientPlugin
from regipy_tests.validation.validation import ValidationCase


class SusclientPluginValidationCase(ValidationCase):
    plugin = SusclientPlugin
    test_hive_file_name = "software.xz"
    exact_expected_result = None

            