from regipy.plugins.system.disablelastaccess import DisableLastAccessPlugin
from regipy_tests.validation.validation import ValidationCase


class DisableLastAccessPluginValidationCase(ValidationCase):
    plugin = DisableLastAccessPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = {
        "\\ControlSet001\\Control\\FileSystem": {
            "last_write": "2009-07-14T04:37:09.429568+00:00",
            "NtfsDisableLastAccessUpdate": "1",
            "NtfsDisableLastAccessUpdateStr": "",
        },
        "\\ControlSet002\\Control\\FileSystem": {
            "last_write": "2009-07-14T04:37:09.429568+00:00",
            "NtfsDisableLastAccessUpdate": "1",
            "NtfsDisableLastAccessUpdateStr": "",
        },
    }
