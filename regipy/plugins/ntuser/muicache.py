"""
MUICache plugin - Parses MUI Cache entries (application display names)
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

# Windows Vista+ path
MUICACHE_PATH_VISTA = r"\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
# Windows XP path
MUICACHE_PATH_XP = r"\Software\Microsoft\Windows\ShellNoRoam\MUICache"


class MUICachePlugin(Plugin):
    """
    Parses MUICache entries from NTUSER.DAT or UsrClass.dat
    MUICache stores the display names of applications that have been run.
    """

    NAME = "muicache"
    DESCRIPTION = "Parses MUI Cache (application display names)"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        logger.debug("Started MUICache Plugin...")

        # Try Vista+ path first
        muicache_found = self._parse_muicache(MUICACHE_PATH_VISTA)

        # Try XP path if Vista+ not found
        if not muicache_found:
            self._parse_muicache(MUICACHE_PATH_XP)

    def _parse_muicache(self, path: str) -> bool:
        """Parse MUICache at the given path"""
        try:
            muicache_key = self.registry_hive.get_key(path)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find MUICache at: {path}")
            return False

        entry = {
            "key_path": path,
            "last_write": convert_wintime(muicache_key.header.last_modified, as_json=self.as_json),
            "applications": [],
        }

        for value in muicache_key.iter_values():
            # Skip system values
            if value.name.startswith("@") or value.name == "LangID":
                continue

            app_entry = {
                "path": value.name,
                "display_name": value.value if isinstance(value.value, str) else None,
            }

            # Extract just the filename from the path for easier reading
            if "\\" in value.name:
                app_entry["filename"] = value.name.split("\\")[-1]
            else:
                app_entry["filename"] = value.name

            entry["applications"].append(app_entry)

        if entry["applications"]:
            self.entries.append(entry)
            return True

        return False
