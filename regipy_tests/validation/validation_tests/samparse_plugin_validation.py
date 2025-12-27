from regipy.plugins.sam.samparse import SAMParsePlugin
from regipy_tests.validation.validation import ValidationCase


class SAMParsePluginValidationCase(ValidationCase):
    plugin = SAMParsePlugin
    test_hive_file_name = "SAM.xz"

    expected_entries = [
        {
            "key_path": "\\SAM\\Domains\\Account\\Users\\000001F4",
            "rid": 500,
            "last_write": "2014-09-24T06:32:50.378042+00:00",
            "last_login": "2010-11-20T21:48:12.569244+00:00",
            "password_last_set": "2010-11-20T21:56:34.743687+00:00",
            "account_expires": None,
            "last_failed_login": None,
            "account_flags": 529,
            "account_flags_parsed": [
                "Account Disabled",
                "Normal User Account",
                "Password Does Not Expire",
            ],
            "failed_login_count": 0,
            "login_count": 6,
        },
        {
            "key_path": "\\SAM\\Domains\\Account\\Users\\000003E8",
            "rid": 1000,
            "last_write": "2014-09-30T02:59:34.316692+00:00",
            "last_login": "2014-09-30T02:59:34.316693+00:00",
            "password_last_set": "2014-09-24T03:35:45.844801+00:00",
            "account_expires": None,
            "last_failed_login": None,
            "account_flags": 16,
            "account_flags_parsed": ["Normal User Account"],
            "failed_login_count": 0,
            "login_count": 4,
        },
    ]
    expected_entries_count = 3
