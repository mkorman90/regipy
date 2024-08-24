from regipy.plugins.system.diag_sr import DiagSRPlugin
from regipy_tests.validation.validation import ValidationCase


class DiagSRPluginValidationCase(ValidationCase):
    plugin = DiagSRPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Services\\VSS\\Diag\\SystemRestore": {
            "last_write": "2012-03-31T04:00:22.998834+00:00",
            "SrCreateRp (Enter)": "2012-03-31 04:00:01",
            "SrCreateRp (Leave)": "2012-03-31 04:00:22",
        },
        "\\ControlSet002\\Services\\VSS\\Diag\\SystemRestore": {
            "last_write": "2012-03-31T04:00:22.998834+00:00",
            "SrCreateRp (Enter)": "2012-03-31 04:00:01",
            "SrCreateRp (Leave)": "2012-03-31 04:00:22",
        },
    }
