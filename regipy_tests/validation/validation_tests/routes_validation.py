from regipy.plugins.system.routes import RoutesPlugin
from regipy_tests.validation.validation import ValidationCase


class RoutesPluginValidationCase(ValidationCase):
    plugin = RoutesPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = None

            