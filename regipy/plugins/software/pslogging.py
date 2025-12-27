"""
PowerShell Logging plugin - Parses PowerShell logging configuration
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

# PowerShell policy paths
PS_POLICY_PATH = r"\Policies\Microsoft\Windows\PowerShell"
PS_SCRIPTBLOCK_PATH = r"\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
PS_MODULE_PATH = r"\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
PS_TRANSCRIPTION_PATH = r"\Policies\Microsoft\Windows\PowerShell\Transcription"


class PowerShellLoggingPlugin(Plugin):
    """
    Parses PowerShell logging configuration from SOFTWARE hive

    Extracts:
    - Script Block Logging settings
    - Module Logging settings
    - Transcription settings
    - Execution Policy

    These settings are important for security monitoring and incident response.

    Registry Key: Policies\\Microsoft\\Windows\\PowerShell
    """

    NAME = "powershell_logging"
    DESCRIPTION = "Parses PowerShell logging and execution policy"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started PowerShell Logging Plugin...")

        self._parse_main_policy()
        self._parse_scriptblock_logging()
        self._parse_module_logging()
        self._parse_transcription()

    def _parse_main_policy(self):
        """Parse main PowerShell policy settings"""
        try:
            ps_key = self.registry_hive.get_key(PS_POLICY_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find PowerShell policy at: {PS_POLICY_PATH}")
            return

        entry = {
            "type": "policy",
            "key_path": PS_POLICY_PATH,
            "last_write": convert_wintime(ps_key.header.last_modified, as_json=self.as_json),
        }

        for value in ps_key.iter_values():
            name = value.name
            val = value.value

            if name == "EnableScripts":
                entry["scripts_enabled"] = val == 1
            elif name == "ExecutionPolicy":
                entry["execution_policy"] = val

        if len(entry) > 3:
            self.entries.append(entry)

    def _parse_scriptblock_logging(self):
        """Parse Script Block Logging settings"""
        try:
            sb_key = self.registry_hive.get_key(PS_SCRIPTBLOCK_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find ScriptBlockLogging at: {PS_SCRIPTBLOCK_PATH}")
            return

        entry = {
            "type": "scriptblock_logging",
            "key_path": PS_SCRIPTBLOCK_PATH,
            "last_write": convert_wintime(sb_key.header.last_modified, as_json=self.as_json),
        }

        for value in sb_key.iter_values():
            name = value.name
            val = value.value

            if name == "EnableScriptBlockLogging":
                entry["enabled"] = val == 1
            elif name == "EnableScriptBlockInvocationLogging":
                entry["invocation_logging_enabled"] = val == 1

        self.entries.append(entry)

    def _parse_module_logging(self):
        """Parse Module Logging settings"""
        try:
            ml_key = self.registry_hive.get_key(PS_MODULE_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find ModuleLogging at: {PS_MODULE_PATH}")
            return

        entry = {
            "type": "module_logging",
            "key_path": PS_MODULE_PATH,
            "last_write": convert_wintime(ml_key.header.last_modified, as_json=self.as_json),
        }

        for value in ml_key.iter_values():
            name = value.name
            val = value.value

            if name == "EnableModuleLogging":
                entry["enabled"] = val == 1

        # Check for module names subkey
        try:
            modules_key = self.registry_hive.get_key(f"{PS_MODULE_PATH}\\ModuleNames")
            module_names = []
            for value in modules_key.iter_values():
                module_names.append(value.name)
            if module_names:
                entry["logged_modules"] = module_names
        except RegistryKeyNotFoundException:
            pass

        self.entries.append(entry)

    def _parse_transcription(self):
        """Parse Transcription settings"""
        try:
            tr_key = self.registry_hive.get_key(PS_TRANSCRIPTION_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find Transcription at: {PS_TRANSCRIPTION_PATH}")
            return

        entry = {
            "type": "transcription",
            "key_path": PS_TRANSCRIPTION_PATH,
            "last_write": convert_wintime(tr_key.header.last_modified, as_json=self.as_json),
        }

        for value in tr_key.iter_values():
            name = value.name
            val = value.value

            if name == "EnableTranscripting":
                entry["enabled"] = val == 1
            elif name == "OutputDirectory":
                entry["output_directory"] = val
            elif name == "EnableInvocationHeader":
                entry["invocation_header_enabled"] = val == 1

        self.entries.append(entry)
