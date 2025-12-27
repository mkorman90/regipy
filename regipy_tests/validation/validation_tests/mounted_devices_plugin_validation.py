from regipy.plugins.system.mountdev import MountedDevicesPlugin
from regipy_tests.validation.validation import ValidationCase


class MountedDevicesPluginValidationCase(ValidationCase):
    plugin = MountedDevicesPlugin
    test_hive_file_name = "SYSTEM.xz"

    expected_entries = [
        {
            "key_path": "\\MountedDevices",
            "last_write": "2011-07-05T19:33:28.328124+00:00",
            "value_name": "\\DosDevices\\C:",
            "mount_point": "C:",
            "mount_type": "drive_letter",
        }
    ]
    expected_entries_count = 11
