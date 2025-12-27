"""
AppKeys plugin - Parses application-specific keyboard shortcuts
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

APPKEYS_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\AppKey"


class AppKeysPlugin(Plugin):
    """
    Parses Application Keys from NTUSER.DAT
    Registry Key: Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AppKey
    These are keyboard shortcuts that launch specific applications.
    """

    NAME = "appkeys"
    DESCRIPTION = "Parses application keyboard shortcuts"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        logger.debug("Started AppKeys Plugin...")

        try:
            appkeys_key = self.registry_hive.get_key(APPKEYS_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.debug(f"Could not find {self.NAME} plugin data at: {APPKEYS_PATH}: {ex}")
            return

        for subkey in appkeys_key.iter_subkeys():
            key_id = subkey.name
            subkey_path = f"{APPKEYS_PATH}\\{key_id}"

            entry = {
                "key_path": subkey_path,
                "key_id": key_id,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            }

            for value in subkey.iter_values():
                if value.name == "ShellExecute":
                    entry["shell_execute"] = value.value
                elif value.name == "Association":
                    entry["association"] = value.value
                elif value.name == "RegisteredApp":
                    entry["registered_app"] = value.value

            # [comment] why filter?
            if "shell_execute" in entry or "association" in entry or "registered_app" in entry:
                self.entries.append(entry)
