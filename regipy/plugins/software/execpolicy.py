"""
Execution Policy plugin - Parses PowerShell and script execution policies
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.plugins.utils import extract_values
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

# PowerShell execution policy paths
PS_SHELL_IDS_PATH = r"\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
PS_POLICY_PATH = r"\Policies\Microsoft\Windows\PowerShell"

# Script execution paths
WSH_SETTINGS_PATH = r"\Microsoft\Windows Script Host\Settings"


class ExecutionPolicyPlugin(Plugin):
    """
    Parses execution policies from SOFTWARE hive

    Extracts:
    - PowerShell execution policy
    - Windows Script Host (WSH) settings

    Registry Keys:
    - Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell
    - Policies\\Microsoft\\Windows\\PowerShell
    - Microsoft\\Windows Script Host\\Settings
    """

    NAME = "execution_policy"
    DESCRIPTION = "Parses PowerShell and script execution policies"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started Execution Policy Plugin...")

        self._parse_powershell_policy()
        self._parse_powershell_group_policy()
        self._parse_wsh_settings()

    def _parse_powershell_policy(self):
        """Parse PowerShell execution policy"""
        try:
            ps_key = self.registry_hive.get_key(PS_SHELL_IDS_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find PowerShell ShellIds at: {PS_SHELL_IDS_PATH}")
            return

        entry = {
            "type": "powershell",
            "key_path": PS_SHELL_IDS_PATH,
            "last_write": convert_wintime(ps_key.header.last_modified, as_json=self.as_json),
        }

        extract_values(
            ps_key,
            {
                "ExecutionPolicy": "execution_policy",
                "Path": "path",
            },
            entry,
        )

        self.entries.append(entry)

    def _parse_powershell_group_policy(self):
        """Parse PowerShell Group Policy settings"""
        try:
            gp_key = self.registry_hive.get_key(PS_POLICY_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find PowerShell policy at: {PS_POLICY_PATH}")
            return

        entry = {
            "type": "powershell_policy",
            "key_path": PS_POLICY_PATH,
            "last_write": convert_wintime(gp_key.header.last_modified, as_json=self.as_json),
        }

        extract_values(
            gp_key,
            {
                "ExecutionPolicy": "execution_policy",
                "EnableScripts": ("scripts_enabled", lambda v: v == 1),
            },
            entry,
        )

        if "execution_policy" in entry or "scripts_enabled" in entry:
            self.entries.append(entry)

    def _parse_wsh_settings(self):
        """Parse Windows Script Host settings"""
        try:
            wsh_key = self.registry_hive.get_key(WSH_SETTINGS_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find WSH Settings at: {WSH_SETTINGS_PATH}")
            return

        entry = {
            "type": "wsh",
            "key_path": WSH_SETTINGS_PATH,
            "last_write": convert_wintime(wsh_key.header.last_modified, as_json=self.as_json),
        }

        extract_values(
            wsh_key,
            {
                "Enabled": ("enabled", lambda v: v != 0),
                "Remote": ("remote_enabled", lambda v: v == 1),
                "TrustPolicy": "trust_policy",
                "IgnoreUserSettings": ("ignore_user_settings", lambda v: v == 1),
                "LogSecuritySuccesses": ("log_security_successes", lambda v: v == 1),
                "DisplayLogo": ("display_logo", lambda v: v == 1),
            },
            entry,
        )

        if len(entry) > 3:
            self.entries.append(entry)
