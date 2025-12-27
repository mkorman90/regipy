"""
RunMRU plugin - Parses Run dialog history
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

RUN_MRU_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"


class RunMRUPlugin(Plugin):
    """
    Parses Run dialog MRU (Most Recently Used) list from NTUSER.DAT
    Registry Key: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU
    """

    NAME = "runmru"
    DESCRIPTION = "Parses Run dialog MRU list"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        logger.debug("Started RunMRU Plugin...")

        try:
            runmru_key = self.registry_hive.get_key(RUN_MRU_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.debug(f"Could not find {self.NAME} plugin data at: {RUN_MRU_PATH}: {ex}")
            return

        entry = {
            "key_path": RUN_MRU_PATH,
            "last_write": convert_wintime(runmru_key.header.last_modified, as_json=self.as_json),
            "mru_order": None,
            "commands": [],
        }

        mru_list = None
        mru_values = {}

        for value in runmru_key.iter_values():
            if value.name == "MRUList":
                # MRUList contains the order as a string of letters (e.g., "dcba")
                mru_list = value.value
            elif len(value.name) == 1 and value.name.isalpha():
                # Single letter values (a, b, c, etc.) contain the commands
                # Commands end with \1 which indicates the command was typed
                command = value.value
                if command and isinstance(command, str):
                    # Remove the trailing \1 marker if present
                    command = command.rstrip("\x01")
                    mru_values[value.name] = command

        if mru_list:
            entry["mru_order"] = mru_list

        # Build ordered list based on MRUList
        if mru_list and mru_values:
            for letter in mru_list:
                if letter in mru_values:
                    entry["commands"].append({"letter": letter, "command": mru_values[letter]})

        if entry["commands"] or entry["mru_order"]:
            self.entries.append(entry)
