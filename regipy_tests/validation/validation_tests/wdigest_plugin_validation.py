from regipy.plugins.system.wdigest import WDIGESTPlugin
from regipy_tests.validation.validation import ValidationCase


class WDIGESTPluginValidationCase(ValidationCase):
    plugin = WDIGESTPlugin
    test_hive_file_name = "SYSTEM.xz"
    exact_expected_result = [
        {
            "subkey": "\\ControlSet001\\Control\\SecurityProviders\\WDigest",
            "timestamp": "2009-07-14T04:37:09.491968+00:00",
            "use_logon_credential": 1,
        },
        {
            "subkey": "\\ControlSet002\\Control\\SecurityProviders\\WDigest",
            "timestamp": "2009-07-14T04:37:09.491968+00:00",
            "use_logon_credential": None,
        },
    ]
