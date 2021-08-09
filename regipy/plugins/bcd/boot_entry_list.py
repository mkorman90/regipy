"""
Windows Boot Configuration Data (BCD) boot entry list plugin
"""

import logging
import uuid

from typing import Union

from regipy.registry import NKRecord
from regipy.hive_types import BCD_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

# BCD object store key path
# See https://www.geoffchappell.com/notes/windows/boot/bcd/objects.htm
BCD_OBJECTS_PATH = r"\Objects"

# Relevant BCD object element types:

# BcdLibraryDevice_ApplicationDevice
ELEM_TYPE_APPLICATION_DEVICE = 0x11000001
# BcdLibraryString_ApplicationPath
ELEM_TYPE_APPLICATION_PATH = 0x12000002
# BcdLibraryString_Description
ELEM_TYPE_DESCRIPTION = 0x12000004


def _get_element_by_type(obj_key: NKRecord, datatype: int) -> Union[str, bytes, None]:
    """
    Retrieves stored BCD object elements by their datatype.

    See https://www.geoffchappell.com/notes/windows/boot/bcd/elements.htm
    """

    # The BCD object attributes are stored as "elements" instead of normal values
    elements_key = obj_key.get_subkey("Elements")
    if elements_key.subkey_count == 0:
        return None

    elem_key = elements_key.get_subkey("%08X" % datatype)
    if elem_key is None:
        return None

    return elem_key.get_value("Element")


class BootEntryListPlugin(Plugin):
    """
    Windows Boot Configuration Data (BCD) boot entry list extractor
    """

    NAME = "boot_entry_list"
    DESCRIPTION = "List the Windows BCD boot entries"
    COMPATIBLE_HIVE = BCD_HIVE_TYPE

    def run(self) -> None:
        logger.info("Started Boot Entry List Plugin...")

        objects_key = self.registry_hive.get_key(BCD_OBJECTS_PATH)

        for obj_key in objects_key.iter_subkeys():
            desc_key = obj_key.get_subkey("Description")
            # Object type defines the boot entry features
            desc_type = desc_key.get_value("Type")

            # The remaining boot entry attributes are stored as object elements
            desc_name = _get_element_by_type(obj_key, ELEM_TYPE_DESCRIPTION)
            path_name = _get_element_by_type(obj_key, ELEM_TYPE_APPLICATION_PATH)
            device_data = _get_element_by_type(obj_key, ELEM_TYPE_APPLICATION_DEVICE)

            # Filter out objects that do not look like boot entries
            if desc_name is None or path_name is None or device_data is None:
                continue

            # TODO: Figure out the device data blob format
            if not isinstance(device_data, bytes) or len(device_data) < 72:
                continue

            # TODO: Figure out how non-GPT partitions are encoded
            gpt_part_guid = str(uuid.UUID(bytes_le=device_data[32:48]))
            gpt_disk_guid = str(uuid.UUID(bytes_le=device_data[56:72]))

            entry_type = "0x%08X" % desc_type if self.as_json else desc_type

            self.entries.append(
                {
                    "guid": obj_key.name,
                    "type": entry_type,
                    "name": desc_name,
                    "gpt_disk": gpt_disk_guid,
                    "gpt_partition": gpt_part_guid,
                    "image_path": path_name,
                    "timestamp": convert_wintime(
                        obj_key.header.last_modified, as_json=self.as_json
                    ),
                }
            )
