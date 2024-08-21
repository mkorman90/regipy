
from regipy.plugins.software.spp_clients import SppClientsPlugin
from regipy_tests.validation.validation import ValidationCase


class SppClientsPluginValidationCase(ValidationCase):
    plugin = SppClientsPlugin
    test_hive_file_name = "software.xz"
    exact_expected_result = None

            