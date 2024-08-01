from regipy.plugins.system.computer_name import ComputerNamePlugin
from regipy_tests.validation.validation import ValidationCase


class ComputerNamePluginValidationCase(ValidationCase):
    plugin = ComputerNamePlugin
    test_hive_file_name = "SYSTEM.xz"

    exact_expected_result = [
        {"name": "WKS-WIN732BITA", "timestamp": "2010-11-10T17:18:08.718750+00:00"},
        {"name": "WIN-V5T3CSP8U4H", "timestamp": "2010-11-10T18:17:36.968750+00:00"},
    ]