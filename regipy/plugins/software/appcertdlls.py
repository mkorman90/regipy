"""
AppCertDLLs plugin - Parses persistence via AppCertDLLs
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

APPCERTDLLS_PATH = r"\Microsoft\Windows NT\CurrentVersion\Windows"


class AppCertDLLsPlugin(Plugin):
    """
    Parses AppCertDLLs persistence mechanism from SOFTWARE hive

    AppCertDLLs contains DLLs that are loaded into every process that calls
    CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW,
    CreateProcessWithTokenW, or WinExec.

    This is a known persistence and code injection technique.

    Registry Key: Microsoft\\Windows NT\\CurrentVersion\\Windows
    Value: AppCertDLLs (REG_MULTI_SZ)
    """

    NAME = "appcert_dlls"
    DESCRIPTION = "Parses AppCertDLLs persistence entries"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started AppCertDLLs Plugin...")

        try:
            windows_key = self.registry_hive.get_key(APPCERTDLLS_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.debug(f"Could not find AppCertDLLs at: {APPCERTDLLS_PATH}: {ex}")
            return

        for value in windows_key.iter_values():
            if value.name == "AppCertDLLs":
                entry = {
                    "key_path": APPCERTDLLS_PATH,
                    "last_write": convert_wintime(windows_key.header.last_modified, as_json=self.as_json),
                    "appcert_dlls": value.value,
                }
                self.entries.append(entry)
                break
