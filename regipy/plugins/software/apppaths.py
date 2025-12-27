"""
App Paths plugin - Parses application paths registry entries
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

APP_PATHS_PATH = r"\Microsoft\Windows\CurrentVersion\App Paths"
APP_PATHS_WOW64_PATH = r"\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths"


class AppPathsPlugin(Plugin):
    """
    Parses App Paths from SOFTWARE hive

    App Paths allows applications to be launched by name without specifying
    the full path. Each subkey under App Paths is an executable name, and
    contains the path to the actual executable.

    This is useful for:
    - Finding installed applications
    - Detecting persistence (malware can hijack app paths)
    - Understanding application configurations

    Registry Keys:
    - Microsoft\\Windows\\CurrentVersion\\App Paths
    - Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths
    """

    NAME = "app_paths"
    DESCRIPTION = "Parses application paths registry entries"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started App Paths Plugin...")

        self._parse_app_paths(APP_PATHS_PATH, "x64")
        self._parse_app_paths(APP_PATHS_WOW64_PATH, "x86")

    def _parse_app_paths(self, path: str, architecture: str):
        """Parse App Paths at the given path"""
        try:
            app_paths_key = self.registry_hive.get_key(path)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find App Paths at: {path}")
            return

        for subkey in app_paths_key.iter_subkeys():
            app_name = subkey.name
            subkey_path = f"{path}\\{app_name}"

            entry = {
                "key_path": subkey_path,
                "application": app_name,
                "architecture": architecture,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            }

            for value in subkey.iter_values():
                name = value.name.lower() if value.name else "(default)"
                val = value.value

                if name == "(default)" or value.name == "":
                    entry["path"] = val
                elif name == "path":
                    entry["app_path"] = val
                elif name == "useurl":
                    entry["use_url"] = val
                elif name == "dropmenu":
                    entry["drop_menu"] = val
                elif name == "dontusedestoolbar":
                    entry["dont_use_des_toolbar"] = val

            self.entries.append(entry)
