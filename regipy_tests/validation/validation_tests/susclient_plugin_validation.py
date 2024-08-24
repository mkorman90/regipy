from regipy.plugins.software.susclient import SusclientPlugin
from regipy_tests.validation.validation import ValidationCase


class SusclientPluginValidationCase(ValidationCase):
    plugin = SusclientPlugin
    test_hive_file_name = "SOFTWARE.xz"
    exact_expected_result = {
        "\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate": {
            "last_write": "2012-03-14T07:05:41.719626+00:00",
            "SusClientId": "50df98f2-964a-496d-976d-d95296e13929",
            "SusClientIdValidation": "",
            "LastRestorePointSetTime": "2012-03-14 07:05:41",
        }
    }
