"""
Sysinternals plugin - Parses Sysinternals tools EULA acceptance records
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

SYSINTERNALS_PATH = r"\Software\Sysinternals"


class SysinternalsPlugin(Plugin):
    """
    Parses Sysinternals EULA acceptance records from NTUSER.DAT
    Registry Key: Software\\Sysinternals

    When a Sysinternals tool is run and the EULA is accepted,
    it creates a subkey with the tool name containing an EulaAccepted value.
    This provides evidence of which Sysinternals tools have been executed.
    """

    NAME = "sysinternals"
    DESCRIPTION = "Parses Sysinternals tools EULA acceptance"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        logger.debug("Started Sysinternals Plugin...")

        try:
            sysinternals_key = self.registry_hive.get_key(SYSINTERNALS_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.debug(f"Could not find {self.NAME} plugin data at: {SYSINTERNALS_PATH}: {ex}")
            return

        for subkey in sysinternals_key.iter_subkeys():
            tool_name = subkey.name
            subkey_path = f"{SYSINTERNALS_PATH}\\{tool_name}"

            entry = {
                "key_path": subkey_path,
                "tool_name": tool_name,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
                "eula_accepted": False,
            }

            for value in subkey.iter_values():
                if value.name == "EulaAccepted":
                    entry["eula_accepted"] = value.value == 1

            self.entries.append(entry)
