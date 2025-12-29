"""
USB Devices plugin - Parses USB device history (Enum\\USB)
"""

import logging
from typing import Optional

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.plugins.utils import extract_values
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

ENUM_USB_PATH = r"Enum\USB"


def strip_resource_ref(val) -> Optional[str]:
    """Remove resource reference prefix if present (e.g., '@oem123.inf,...;Device Name')"""
    if isinstance(val, str) and ";" in val:
        return val.split(";")[-1]
    return val


class USBDevicesPlugin(Plugin):
    """
    Parses USB device history from SYSTEM hive (Enum\\USB)

    This complements USBSTOR by providing information about non-storage USB devices
    such as keyboards, mice, webcams, and other USB peripherals.

    Registry Key: Enum\\USB under each ControlSet
    """

    NAME = "usb_devices"
    DESCRIPTION = "Parses USB device connection history"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started USB Devices Plugin...")

        for controlset_path in self.registry_hive.get_control_sets(ENUM_USB_PATH):
            try:
                usb_key = self.registry_hive.get_key(controlset_path)
            except RegistryKeyNotFoundException:
                logger.debug(f"Could not find USB devices at: {controlset_path}")
                continue

            self._parse_usb_key(usb_key, controlset_path)

    def _parse_usb_key(self, usb_key, base_path: str):
        """Parse USB device entries"""
        # Each subkey is a VID_xxxx&PID_xxxx entry
        for vid_pid_key in usb_key.iter_subkeys():
            vid_pid = vid_pid_key.name
            vid_pid_path = f"{base_path}\\{vid_pid}"

            # Parse VID and PID from the key name
            vid = None
            pid = None
            if "VID_" in vid_pid and "PID_" in vid_pid:
                try:
                    vid_start = vid_pid.index("VID_") + 4
                    vid_end = vid_pid.index("&", vid_start) if "&" in vid_pid[vid_start:] else vid_start + 4
                    vid = vid_pid[vid_start:vid_end]

                    pid_start = vid_pid.index("PID_") + 4
                    pid_end_chars = ["&", "\\"]
                    pid_end = len(vid_pid)
                    for char in pid_end_chars:
                        if char in vid_pid[pid_start:]:
                            pid_end = min(pid_end, vid_pid.index(char, pid_start))
                    pid = vid_pid[pid_start:pid_end]
                except (ValueError, IndexError):
                    pass

            # Each sub-subkey is a serial number or instance ID
            for instance_key in vid_pid_key.iter_subkeys():
                instance_id = instance_key.name
                instance_path = f"{vid_pid_path}\\{instance_id}"

                entry = {
                    "key_path": instance_path,
                    "vid_pid": vid_pid,
                    "vid": vid,
                    "pid": pid,
                    "instance_id": instance_id,
                    "last_write": convert_wintime(instance_key.header.last_modified, as_json=self.as_json),
                }

                extract_values(
                    instance_key,
                    {
                        "DeviceDesc": ("device_desc", strip_resource_ref),
                        "FriendlyName": "friendly_name",
                        "Mfg": ("manufacturer", strip_resource_ref),
                        "Service": "service",
                        "Class": "class",
                        "ClassGUID": "class_guid",
                        "Driver": "driver",
                        "ContainerID": "container_id",
                        "HardwareID": "hardware_id",
                    },
                    entry,
                )

                self.entries.append(entry)
