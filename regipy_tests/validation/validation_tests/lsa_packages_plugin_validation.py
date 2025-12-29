from regipy.plugins.system.lsa_packages import LSAPackagesPlugin
from regipy_tests.validation.validation import ValidationCase


class LSAPackagesPluginValidationCase(ValidationCase):
    plugin = LSAPackagesPlugin
    test_hive_file_name = "SYSTEM.xz"

    expected_entries = [
        {
            "key_path": "\\ControlSet001\\Control\\Lsa",
            "last_write": "2012-04-04T11:47:46.203124+00:00",
            "audit_base_objects": False,
            "audit_base_directories": False,
            "limit_blank_password_use": True,
            "notification_packages": ["scecli"],
            "security_packages": [
                "kerberos",
                "msv1_0",
                "schannel",
                "wdigest",
                "tspkg",
                "pku2u",
            ],
            "authentication_packages": ["msv1_0"],
            "secure_boot": 1,
        }
    ]
    expected_entries_count = 2
