import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

# Ressources : https://patrickwu.space/2020/07/19/wsl-related-registry/

WSL_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Lxss"


class WSLPlugin(Plugin):
    NAME = "wsl"
    DESCRIPTION = "Get WSL information"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def get_wls_info(self, subkey, distribs=None):
        if distribs is None:
            distribs = []

        try:
            flags = subkey.get_value("Flags")
            state = subkey.get_value("State")
            version = subkey.get_value("Version")

            # Initialize the entry for a distribution with its GUID as the key
            distribution_entry = {
                "GUID": subkey.name,
                "last_modified": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
                "wsl_distribution_source_location": subkey.get_value("BasePath"),
                "default_uid": subkey.get_value("DefaultUid"),
                "distribution_name": subkey.get_value("DistributionName"),
                "default_environment": subkey.get_value("DefaultEnvironment"),  # REG_MULTI_SZ
                "flags": flags,
                "kernel_command_line": subkey.get_value("KernelCommandLine"),
                "package_family_name": subkey.get_value("PackageFamilyName"),
                "state": state,
                "filesystem": ("lxfs" if version == 1 else "wslfs" if version == 2 else "Unknown"),
            }

            # Decode flags for additional information
            if flags is not None:
                distribution_entry["enable_interop"] = bool(flags & 0x1)
                distribution_entry["append_nt_path"] = bool(flags & 0x2)
                distribution_entry["enable_drive_mounting"] = bool(flags & 0x4)

            # Decode the state of the distribution
            if state is not None:
                if state == 0x1:
                    distribution_entry["state"] = "Normal"
                elif state == 0x3:
                    distribution_entry["state"] = "Installing"
                elif state == 0x4:
                    distribution_entry["state"] = "Uninstalling"
                else:
                    distribution_entry["state"] = "Unknown"

            # Add the distribution entry with its GUID to the list of distributions
            distribs.append(distribution_entry)

        except Exception as e:
            logger.error(f"Error processing subkey {subkey.name}: {e}")
            raise

        return distribs

    def run(self):
        try:
            # Attempt to get the WSL registry key
            wsl_key = self.registry_hive.get_key(WSL_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f"Registry key not found at path {WSL_PATH}: {ex}")
            return

        self.entries = {
            WSL_PATH: {
                "last_modified": convert_wintime(wsl_key.header.last_modified, as_json=self.as_json),
                "number_of_distrib": wsl_key.header.subkey_count,
                "default_distrib_GUID": wsl_key.get_value("DefaultDistribution"),
                "wsl_version": (
                    "WSL1"
                    if wsl_key.get_value("DefaultVersion") == 1
                    else ("WSL2" if wsl_key.get_value("DefaultVersion") == 2 else "Unknown")
                ),
                "nat_ip_address": wsl_key.get_value("NatIpAddress"),
                "distributions": [],
            }
        }

        try:
            for distrib in wsl_key.iter_subkeys():
                distribs = self.get_wls_info(distrib)
                self.entries[WSL_PATH]["distributions"] = distribs
        except Exception as e:
            logger.error(f"Error iterating over subkeys in {distrib.path}: {e}")
