from regipy.plugins.software.spp_clients import SppClientsPlugin
from regipy_tests.validation.validation import ValidationCase


class SppClientsPluginValidationCase(ValidationCase):
    plugin = SppClientsPlugin
    test_hive_file_name = "SOFTWARE.xz"
    exact_expected_result = {
        "\\Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients": {
            "last_write": "2012-03-15T22:32:18.089574+00:00",
            "{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}": ["\\\\?\\Volume{656b1715-ecf6-11df-92e6-806e6f6e6963}\\:(C:)"],
        }
    }
