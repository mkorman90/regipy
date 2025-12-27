"""
MountedDevices plugin - Parses mounted device information
"""

import logging
import re

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

MOUNTED_DEVICES_PATH = r"\MountedDevices"


def parse_device_data(data: bytes) -> dict:
    """Parse the binary device data to extract device information"""
    result = {}

    if not data:
        return result

    try:
        # Try to decode as unicode path
        decoded = data.decode("utf-16-le", errors="ignore").rstrip("\x00")
        if decoded:
            result["path"] = decoded

            # Extract volume GUID if present
            guid_match = re.search(r"\{[0-9A-Fa-f-]+\}", decoded)
            if guid_match:
                result["volume_guid"] = guid_match.group(0)

            # Check for device type indicators
            if "\\DosDevices\\" in decoded:
                result["type"] = "dos_device"
            elif "\\??\\Volume" in decoded:
                result["type"] = "volume"
            elif "_??_USBSTOR" in decoded or "USBSTOR" in decoded:
                result["type"] = "usb_storage"
            elif "IDE" in decoded or "SCSI" in decoded:
                result["type"] = "disk"

    except Exception:
        pass

    # If no path found, check for disk signature format (12 bytes)
    if "path" not in result and len(data) == 12:
        # First 4 bytes are disk signature, next 8 bytes are partition offset
        try:
            disk_sig = data[0:4].hex()
            partition_offset = int.from_bytes(data[4:12], "little")
            result["disk_signature"] = disk_sig
            result["partition_offset"] = partition_offset
            result["type"] = "mbr_partition"
        except Exception:
            pass

    # Check for GPT disk format (24 bytes)
    if "path" not in result and len(data) == 24:
        try:
            # GPT disks have a different format with GUID
            guid_bytes = data[0:16]
            partition_offset = int.from_bytes(data[16:24], "little")
            # Format GUID
            guid = (
                f"{guid_bytes[3]:02x}{guid_bytes[2]:02x}{guid_bytes[1]:02x}{guid_bytes[0]:02x}-"
                f"{guid_bytes[5]:02x}{guid_bytes[4]:02x}-"
                f"{guid_bytes[7]:02x}{guid_bytes[6]:02x}-"
                f"{guid_bytes[8]:02x}{guid_bytes[9]:02x}-"
                f"{guid_bytes[10]:02x}{guid_bytes[11]:02x}{guid_bytes[12]:02x}"
                f"{guid_bytes[13]:02x}{guid_bytes[14]:02x}{guid_bytes[15]:02x}"
            )
            result["disk_guid"] = guid
            result["partition_offset"] = partition_offset
            result["type"] = "gpt_partition"
        except Exception:
            pass

    return result


class MountedDevicesPlugin(Plugin):
    """
    Parses MountedDevices from SYSTEM hive

    Provides information about:
    - Drive letter assignments
    - Volume mappings
    - USB device volume assignments
    - Disk and partition identifiers

    Registry Key: MountedDevices
    """

    NAME = "mounted_devices"
    DESCRIPTION = "Parses mounted device information"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started MountedDevices Plugin...")

        try:
            mounted_key = self.registry_hive.get_key(MOUNTED_DEVICES_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.debug(f"Could not find MountedDevices at: {MOUNTED_DEVICES_PATH}: {ex}")
            return

        base_entry = {
            "key_path": MOUNTED_DEVICES_PATH,
            "last_write": convert_wintime(mounted_key.header.last_modified, as_json=self.as_json),
        }

        for value in mounted_key.iter_values():
            name = value.name
            data = value.value

            entry = base_entry.copy()
            entry["value_name"] = name

            # Determine mount point type
            if name.startswith("\\DosDevices\\"):
                entry["mount_point"] = name.replace("\\DosDevices\\", "")
                entry["mount_type"] = "drive_letter"
            elif name.startswith("\\??\\Volume"):
                entry["mount_point"] = name
                entry["mount_type"] = "volume"
            elif name == "#{":
                entry["mount_type"] = "database"
            else:
                entry["mount_type"] = "other"

            # Parse the device data
            if isinstance(data, bytes):
                device_info = parse_device_data(data)
                entry.update(device_info)
                entry["data_size"] = len(data)

            self.entries.append(entry)
