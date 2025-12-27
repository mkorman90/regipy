from regipy.plugins.system.usb_devices import USBDevicesPlugin
from regipy_tests.validation.validation import ValidationCase


class USBDevicesPluginValidationCase(ValidationCase):
    plugin = USBDevicesPlugin
    test_hive_file_name = "SYSTEM.xz"

    expected_entries = [
        {
            "key_path": "\\ControlSet001\\Enum\\USB\\ROOT_HUB\\5&391b2433&0",
            "vid_pid": "ROOT_HUB",
            "vid": None,
            "pid": None,
            "instance_id": "5&391b2433&0",
            "last_write": "2012-04-07T10:31:37.625246+00:00",
            "hardware_id": [
                "USB\\ROOT_HUB&VID8086&PID7112&REV0000",
                "USB\\ROOT_HUB&VID8086&PID7112",
                "USB\\ROOT_HUB",
            ],
            "container_id": "{00000000-0000-0000-ffff-ffffffffffff}",
            "service": "usbhub",
            "class_guid": "{36fc9e60-c465-11cf-8056-444553540000}",
            "driver": "{36fc9e60-c465-11cf-8056-444553540000}\\0002",
            "class": "USB",
            "manufacturer": "(Standard USB Host Controller)",
            "device_desc": "USB Root Hub",
        }
    ]
    expected_entries_count = 14
