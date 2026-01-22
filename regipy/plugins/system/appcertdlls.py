import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

SESSION_MANAGER_PATH = r"Control\Session Manager"


class AppCertDLLsPlugin(Plugin):
    """
    Parses AppCertDLLs persistence mechanism from SYSTEM hive

    AppCertDLLs contains DLLs that are loaded into every process that calls
    CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW,
    CreateProcessWithTokenW, or WinExec.

    This is a known persistence and code injection technique.

    Registry Key: ControlSet*\\Control\\Session Manager
    Value: AppCertDLLs (REG_MULTI_SZ)
    """

    NAME = "appcert_dlls"
    DESCRIPTION = "Parses AppCertDLLs persistence entries"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started AppCertDLLs Plugin...")

        for controlset_path in self.registry_hive.get_control_sets(SESSION_MANAGER_PATH):
            try:
                session_manager_key = self.registry_hive.get_key(controlset_path)
            except RegistryKeyNotFoundException:
                logger.debug(f"Could not find Session Manager at: {controlset_path}")
                continue

            for value in session_manager_key.iter_values():
                if value.name == "AppCertDLLs":
                    entry = {
                        "key_path": controlset_path,
                        "last_write": convert_wintime(session_manager_key.header.last_modified, as_json=self.as_json),
                        "appcert_dlls": value.value,
                    }
                    self.entries.append(entry)
                    break
