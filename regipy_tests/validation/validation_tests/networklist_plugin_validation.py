from regipy.plugins.software.networklist import NetworkListPlugin
from regipy_tests.validation.validation import ValidationCase


class NetworkListPluginValidationCase(ValidationCase):
    plugin = NetworkListPlugin
    test_hive_file_name = "SOFTWARE.xz"

    expected_entries = [
        {
            "type": "profile",
            "key_path": "\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\{1EDE3981-5784-4C61-B5A7-CF328A10043E}",
            "profile_guid": "{1EDE3981-5784-4C61-B5A7-CF328A10043E}",
            "last_write": "2012-04-04T11:48:39.392750+00:00",
            "profile_name": "shieldbase.local",
            "description": "shieldbase.local",
            "managed": True,
            "category": "Domain",
            "date_created": None,
            "name_type": "Wired",
            "date_last_connected": None,
        }
    ]
    expected_entries_count = 6
