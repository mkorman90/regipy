"""
ComDlg32 plugin - Parses Open/Save dialog history (OpenSavePidlMRU, OpenSaveMRU)
"""

import logging
from typing import Optional

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

# Windows Vista+ path
OPEN_SAVE_PIDL_MRU_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
# Windows XP path
OPEN_SAVE_MRU_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU"
# Last visited path
LAST_VISITED_PIDL_MRU_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU"


def parse_pidl_mru_value(data: bytes) -> Optional[str]:
    """
    Parse the PIDL MRU value to extract path/filename.
    """
    if not data or len(data) < 4:
        return None

    try:
        # Try to find readable unicode strings
        result_parts = []
        i = 0
        while i < len(data) - 1:
            # Look for printable unicode sequences
            start = i
            while i < len(data) - 1:
                char_code = int.from_bytes(data[i : i + 2], "little")
                # Check if it's a printable character or common path character
                if 0x20 <= char_code <= 0x7E or char_code in [0x5C, 0x2F, 0x3A]:  # \, /, :
                    i += 2
                else:
                    break

            if i - start >= 4:  # At least 2 unicode characters
                try:
                    part = data[start:i].decode("utf-16-le", errors="ignore").strip("\x00")
                    if part and len(part) >= 2:
                        result_parts.append(part)
                except Exception:
                    pass
            i += 2

        # Return the longest meaningful path-like string
        for part in sorted(result_parts, key=len, reverse=True):
            if "\\" in part or "/" in part or "." in part:
                return part
        if result_parts:
            return result_parts[0]
    except Exception:
        pass

    return None


class ComDlg32Plugin(Plugin):
    """
    Parses Open/Save dialog history from NTUSER.DAT
    Provides information about files opened or saved through common dialogs.
    """

    NAME = "comdlg32"
    DESCRIPTION = "Parses Open/Save dialog MRU lists"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        logger.debug("Started ComDlg32 Plugin...")

        # Try OpenSavePidlMRU (Vista+)
        self._parse_open_save_mru(OPEN_SAVE_PIDL_MRU_PATH, "OpenSavePidlMRU")

        # Try OpenSaveMRU (XP)
        self._parse_open_save_mru(OPEN_SAVE_MRU_PATH, "OpenSaveMRU")

        # Try LastVisitedPidlMRU
        self._parse_last_visited_mru(LAST_VISITED_PIDL_MRU_PATH)

    def _parse_open_save_mru(self, base_path: str, mru_type: str):
        """Parse OpenSaveMRU or OpenSavePidlMRU entries"""
        try:
            base_key = self.registry_hive.get_key(base_path)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find {mru_type} at: {base_path}")
            return

        # Process the main key and all extension subkeys
        for subkey in base_key.iter_subkeys():
            extension = subkey.name
            subkey_path = f"{base_path}\\{extension}"

            entry = {
                "key_path": subkey_path,
                "mru_type": mru_type,
                "extension": extension,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
                "items": [],
            }

            mru_list = None
            mru_values = {}

            for value in subkey.iter_values():
                if value.name == "MRUListEx":
                    mru_list = value.value
                elif value.name.isdigit():
                    parsed = parse_pidl_mru_value(value.value)
                    if parsed:
                        mru_values[int(value.name)] = parsed

            # Build ordered list
            if mru_list and mru_values:
                for i in range(0, len(mru_list) - 4, 4):
                    index = int.from_bytes(mru_list[i : i + 4], "little", signed=True)
                    if index == -1:
                        break
                    if index in mru_values:
                        entry["items"].append({"index": index, "path": mru_values[index]})

            if entry["items"]:
                self.entries.append(entry)

    def _parse_last_visited_mru(self, path: str):
        """Parse LastVisitedPidlMRU entries"""
        try:
            key = self.registry_hive.get_key(path)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find LastVisitedPidlMRU at: {path}")
            return

        entry = {
            "key_path": path,
            "mru_type": "LastVisitedPidlMRU",
            "last_write": convert_wintime(key.header.last_modified, as_json=self.as_json),
            "items": [],
        }

        mru_list = None
        mru_values = {}

        for value in key.iter_values():
            if value.name == "MRUListEx":
                mru_list = value.value
            elif value.name.isdigit():
                parsed = parse_pidl_mru_value(value.value)
                if parsed:
                    mru_values[int(value.name)] = parsed

        if mru_list and mru_values:
            for i in range(0, len(mru_list) - 4, 4):
                index = int.from_bytes(mru_list[i : i + 4], "little", signed=True)
                if index == -1:
                    break
                if index in mru_values:
                    entry["items"].append({"index": index, "path": mru_values[index]})

        if entry["items"]:
            self.entries.append(entry)
