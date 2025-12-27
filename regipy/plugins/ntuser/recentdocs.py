"""
RecentDocs plugin - Parses recently opened documents from the registry
"""

import logging
from typing import Optional

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

RECENT_DOCS_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"


def parse_mru_value(data: bytes) -> Optional[str]:
    """
    Parse the binary MRU value to extract the filename.
    The format is: filename (null-terminated unicode) + shell item data
    """
    if not data:
        return None

    try:
        # Find the null terminator for the unicode string
        null_pos = 0
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                null_pos = i
                break

        if null_pos > 0:
            return data[:null_pos].decode("utf-16-le", errors="replace")
    except Exception:
        pass

    return None


class RecentDocsPlugin(Plugin):
    """
    Parses Recently opened documents from NTUSER.DAT
    Registry Key: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs
    """

    NAME = "recentdocs"
    DESCRIPTION = "Parses recently opened documents"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        logger.debug("Started RecentDocs Plugin...")

        try:
            recent_docs_key = self.registry_hive.get_key(RECENT_DOCS_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.debug(f"Could not find {self.NAME} plugin data at: {RECENT_DOCS_PATH}: {ex}")
            return

        # Process the main RecentDocs key
        self._process_recent_docs_key(recent_docs_key, RECENT_DOCS_PATH)

        # Process extension subkeys (e.g., .txt, .docx, .pdf, etc.)
        for subkey in recent_docs_key.iter_subkeys():
            subkey_path = f"{RECENT_DOCS_PATH}\\{subkey.name}"
            self._process_recent_docs_key(subkey, subkey_path, extension=subkey.name)

    def _process_recent_docs_key(self, key, key_path: str, extension: str = None):
        """Process a RecentDocs key and extract document entries"""
        entry = {
            "key_path": key_path,
            "last_write": convert_wintime(key.header.last_modified, as_json=self.as_json),
            "extension": extension,
            "documents": [],
        }

        mru_list = None
        mru_values = {}

        for value in key.iter_values():
            if value.name == "MRUListEx":
                # MRUListEx contains the order of recently accessed items
                # It's an array of DWORDs representing indices
                mru_list = value.value
            elif value.name.isdigit():
                # Numeric values contain the actual document data
                parsed_name = parse_mru_value(value.value)
                if parsed_name:
                    mru_values[int(value.name)] = parsed_name

        # Build ordered list of documents based on MRUListEx
        if mru_list and mru_values:
            # MRUListEx is a binary blob of 4-byte integers
            for i in range(0, len(mru_list) - 4, 4):
                index = int.from_bytes(mru_list[i : i + 4], "little", signed=True)
                if index == -1:  # End marker
                    break
                if index in mru_values:
                    entry["documents"].append({"index": index, "name": mru_values[index]})

        if entry["documents"]:
            self.entries.append(entry)
