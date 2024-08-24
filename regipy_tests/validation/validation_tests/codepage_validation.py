from regipy.plugins.system.codepage import CodepagePlugin
from regipy_tests.validation.validation import ValidationCase


class CodepagePluginValidationCase(ValidationCase):
    plugin = CodepagePlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Control\\Nls\\CodePage": {
            "last_write": "2009-07-14T04:37:09.460768+00:00",
            "ACP": "1252",
        },
        "\\ControlSet002\\Control\\Nls\\CodePage": {
            "last_write": "2009-07-14T04:37:09.460768+00:00",
            "ACP": "1252",
        },
    }
