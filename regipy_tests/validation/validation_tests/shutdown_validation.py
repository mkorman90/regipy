from regipy.plugins.system.shutdown import ShutdownPlugin
from regipy_tests.validation.validation import ValidationCase


class ShutdownPluginValidationCase(ValidationCase):
    plugin = ShutdownPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Control\\Windows": {
            "last_write": "2012-04-04T01:58:40.839250+00:00",
            "date": "2012-04-04 01:58:40",
        },
        "\\ControlSet002\\Control\\Windows": {
            "last_write": "2012-04-04T01:58:40.839250+00:00",
            "date": "2012-04-04 01:58:40",
        },
    }
