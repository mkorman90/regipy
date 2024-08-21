
from regipy.plugins.software.disablesr import DisableSRPlugin
from regipy_tests.validation.validation import ValidationCase


class DisableSRPluginValidationCase(ValidationCase):
    plugin = DisableSRPlugin
    test_hive_file_name = "software.xz"
    exact_expected_result = None

            