"""
Windows Defender plugin - Parses Windows Defender configuration
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.plugins.utils import extract_values
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

DEFENDER_PATH = r"\Microsoft\Windows Defender"
DEFENDER_POLICY_PATH = r"\Policies\Microsoft\Windows Defender"
DEFENDER_EXCLUSIONS_PATH = r"\Microsoft\Windows Defender\Exclusions"


class WindowsDefenderPlugin(Plugin):
    """
    Parses Windows Defender configuration from SOFTWARE hive

    Extracts:
    - Defender enabled/disabled status
    - Real-time protection settings
    - Exclusions (paths, processes, extensions)
    - Policy overrides

    Registry Keys:
    - Microsoft\\Windows Defender
    - Policies\\Microsoft\\Windows Defender
    """

    NAME = "windows_defender"
    DESCRIPTION = "Parses Windows Defender configuration and exclusions"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started Windows Defender Plugin...")

        self._parse_defender_config()
        self._parse_defender_policy()
        self._parse_exclusions()

    def _parse_defender_config(self):
        """Parse main Defender configuration"""
        try:
            defender_key = self.registry_hive.get_key(DEFENDER_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find Windows Defender at: {DEFENDER_PATH}")
            return

        entry = {
            "type": "configuration",
            "key_path": DEFENDER_PATH,
            "last_write": convert_wintime(defender_key.header.last_modified, as_json=self.as_json),
        }

        extract_values(
            defender_key,
            {
                "DisableAntiSpyware": ("antispyware_disabled", lambda v: v == 1),
                "DisableAntiVirus": ("antivirus_disabled", lambda v: v == 1),
                "ProductStatus": "product_status",
                "InstallLocation": "install_location",
            },
            entry,
        )

        # Parse Real-Time Protection subkey
        try:
            rtp_key = self.registry_hive.get_key(f"{DEFENDER_PATH}\\Real-Time Protection")
            extract_values(
                rtp_key,
                {
                    "DisableRealtimeMonitoring": ("realtime_monitoring_disabled", lambda v: v == 1),
                    "DisableBehaviorMonitoring": ("behavior_monitoring_disabled", lambda v: v == 1),
                    "DisableOnAccessProtection": ("on_access_protection_disabled", lambda v: v == 1),
                    "DisableScanOnRealtimeEnable": ("scan_on_realtime_enable_disabled", lambda v: v == 1),
                },
                entry,
            )
        except RegistryKeyNotFoundException:
            pass

        self.entries.append(entry)

    def _parse_defender_policy(self):
        """Parse Defender Group Policy settings"""
        try:
            policy_key = self.registry_hive.get_key(DEFENDER_POLICY_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find Windows Defender policy at: {DEFENDER_POLICY_PATH}")
            return

        entry = {
            "type": "policy",
            "key_path": DEFENDER_POLICY_PATH,
            "last_write": convert_wintime(policy_key.header.last_modified, as_json=self.as_json),
        }

        extract_values(
            policy_key,
            {
                "DisableAntiSpyware": ("policy_antispyware_disabled", lambda v: v == 1),
                "DisableAntiVirus": ("policy_antivirus_disabled", lambda v: v == 1),
                "DisableRoutinelyTakingAction": ("routine_action_disabled", lambda v: v == 1),
            },
            entry,
        )

        # Check for Real-Time Protection policy
        try:
            rtp_policy_key = self.registry_hive.get_key(f"{DEFENDER_POLICY_PATH}\\Real-Time Protection")
            extract_values(
                rtp_policy_key,
                {
                    "DisableRealtimeMonitoring": ("policy_realtime_monitoring_disabled", lambda v: v == 1),
                },
                entry,
            )
        except RegistryKeyNotFoundException:
            pass

        if len(entry) > 3:  # More than just type, key_path, last_write
            self.entries.append(entry)

    def _parse_exclusions(self):
        """Parse Defender exclusions"""
        exclusion_types = {
            "Paths": "path_exclusions",
            "Processes": "process_exclusions",
            "Extensions": "extension_exclusions",
            "IpAddresses": "ip_exclusions",
        }

        for exclusion_type in exclusion_types:
            path = f"{DEFENDER_EXCLUSIONS_PATH}\\{exclusion_type}"
            try:
                exclusions_key = self.registry_hive.get_key(path)
            except RegistryKeyNotFoundException:
                continue

            exclusions = []
            for value in exclusions_key.iter_values():
                # Value name is the excluded item
                exclusions.append(value.name)

            if exclusions:
                entry = {
                    "type": "exclusion",
                    "exclusion_type": exclusion_type.lower(),
                    "key_path": path,
                    "last_write": convert_wintime(exclusions_key.header.last_modified, as_json=self.as_json),
                    "exclusions": exclusions,
                }
                self.entries.append(entry)
