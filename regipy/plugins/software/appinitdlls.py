"""
AppInit_DLLs plugin - Parses persistence via AppInit_DLLs
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

# 32-bit path
APPINIT_DLLS_PATH = r"\Microsoft\Windows NT\CurrentVersion\Windows"
# 64-bit path (WoW6432Node)
APPINIT_DLLS_WOW64_PATH = r"\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"


class AppInitDLLsPlugin(Plugin):
    """
    Parses AppInit_DLLs persistence mechanism from SOFTWARE hive

    AppInit_DLLs is a registry value that causes Windows to load specified DLLs
    into every user-mode process that links to User32.dll. This is a known
    persistence mechanism used by malware.

    Registry Keys:
    - Microsoft\\Windows NT\\CurrentVersion\\Windows
    - Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows (64-bit systems)
    """

    NAME = "appinit_dlls"
    DESCRIPTION = "Parses AppInit_DLLs persistence entries"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started AppInit_DLLs Plugin...")

        self._parse_appinit_dlls(APPINIT_DLLS_PATH, "x64")
        self._parse_appinit_dlls(APPINIT_DLLS_WOW64_PATH, "x86")

    def _parse_appinit_dlls(self, path: str, architecture: str):
        """Parse AppInit_DLLs at the given path"""
        try:
            windows_key = self.registry_hive.get_key(path)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find AppInit_DLLs at: {path}")
            return

        entry = {
            "key_path": path,
            "architecture": architecture,
            "last_write": convert_wintime(windows_key.header.last_modified, as_json=self.as_json),
            "appinit_dlls": None,
            "load_appinit_dlls": None,
            "require_signed_appinit_dlls": None,
        }

        for value in windows_key.iter_values():
            name = value.name
            val = value.value

            if name == "AppInit_DLLs":
                entry["appinit_dlls"] = val
            elif name == "LoadAppInit_DLLs":
                entry["load_appinit_dlls"] = val == 1
            elif name == "RequireSignedAppInit_DLLs":
                entry["require_signed_appinit_dlls"] = val == 1

        # Only add entry if AppInit_DLLs has content or loading is enabled
        if entry["appinit_dlls"] or entry["load_appinit_dlls"]:
            self.entries.append(entry)
