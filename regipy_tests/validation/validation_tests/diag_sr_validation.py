
from regipy.plugins.system.diag_sr import DiagSRPlugin
from regipy_tests.validation.validation import ValidationCase


class DiagSRPluginValidationCase(ValidationCase):
    plugin = DiagSRPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            