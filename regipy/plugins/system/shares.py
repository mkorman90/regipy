"""
Shares plugin - Parses network share configuration
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

LANMAN_SHARES_PATH = r"Services\LanmanServer\Shares"


class SharesPlugin(Plugin):
    """
    Parses network shares from SYSTEM hive

    Provides information about:
    - Configured network shares
    - Share paths and descriptions
    - Share permissions

    Registry Key: Services\\LanmanServer\\Shares under each ControlSet
    """

    NAME = "shares"
    DESCRIPTION = "Parses network share configuration"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started Shares Plugin...")

        for controlset_path in self.registry_hive.get_control_sets(LANMAN_SHARES_PATH):
            try:
                shares_key = self.registry_hive.get_key(controlset_path)
            except RegistryKeyNotFoundException:
                logger.debug(f"Could not find shares at: {controlset_path}")
                continue

            self._parse_shares(shares_key, controlset_path)

    def _parse_shares(self, shares_key, key_path: str):
        """Parse share entries"""
        for value in shares_key.iter_values():
            share_name = value.name
            share_data = value.value

            entry = {
                "key_path": key_path,
                "share_name": share_name,
                "last_write": convert_wintime(shares_key.header.last_modified, as_json=self.as_json),
            }

            # Share data is a REG_MULTI_SZ with key=value pairs
            if isinstance(share_data, list):
                for item in share_data:
                    if "=" in item:
                        key, val = item.split("=", 1)
                        key_lower = key.lower()

                        if key_lower == "path":
                            entry["path"] = val
                        elif key_lower == "remark":
                            entry["remark"] = val
                        elif key_lower == "permissions":
                            entry["permissions"] = val
                        elif key_lower == "maxuses":
                            entry["max_uses"] = int(val) if val.isdigit() else val
                        elif key_lower == "type":
                            entry["type"] = self._get_share_type(int(val) if val.isdigit() else 0)
                        elif key_lower == "cscflags":
                            entry["csc_flags"] = val

            self.entries.append(entry)

    @staticmethod
    def _get_share_type(type_value: int) -> str:
        """Convert share type value to description"""
        types = {
            0: "Disk Drive",
            1: "Print Queue",
            2: "Device",
            3: "IPC",
            0x80000000: "Temporary",
            0x40000000: "Special",
        }

        base_type = type_value & 0x0FFFFFFF
        special = type_value & 0xF0000000

        type_str = types.get(base_type, f"Unknown ({base_type})")

        if special & 0x80000000:
            type_str += " (Temporary)"
        if special & 0x40000000:
            type_str += " (Special)"

        return type_str
