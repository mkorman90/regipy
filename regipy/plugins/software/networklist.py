"""
NetworkList plugin - Parses network connection history
"""

import logging
import struct
from datetime import datetime
from typing import Optional

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

NETWORK_LIST_PATH = r"\Microsoft\Windows NT\CurrentVersion\NetworkList"
PROFILES_PATH = r"\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
SIGNATURES_PATH = r"\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures"
NLAS_PATH = r"\Microsoft\Windows NT\CurrentVersion\NetworkList\Nla\Wireless"


def parse_network_date(data: bytes) -> Optional[str]:
    """Parse the binary date format used in NetworkList"""
    if not data or len(data) < 16:
        return None

    try:
        # Format: Year(2) Month(2) DayOfWeek(2) Day(2) Hour(2) Minute(2) Second(2) Milliseconds(2)
        year = struct.unpack("<H", data[0:2])[0]
        month = struct.unpack("<H", data[2:4])[0]
        # day_of_week = struct.unpack("<H", data[4:6])[0]
        day = struct.unpack("<H", data[6:8])[0]
        hour = struct.unpack("<H", data[8:10])[0]
        minute = struct.unpack("<H", data[10:12])[0]
        second = struct.unpack("<H", data[12:14])[0]
        # milliseconds = struct.unpack("<H", data[14:16])[0]

        if year > 0 and month > 0 and day > 0:
            dt = datetime(year, month, day, hour, minute, second)
            return dt.isoformat()
    except Exception:
        pass

    return None


class NetworkListPlugin(Plugin):
    """
    Parses Network List (NetworkList) from SOFTWARE hive

    Provides information about:
    - Network profiles (wired and wireless networks connected to)
    - First and last connection times
    - Network signatures (MAC addresses, SSIDs)

    Registry Key: Microsoft\\Windows NT\\CurrentVersion\\NetworkList
    """

    NAME = "networklist"
    DESCRIPTION = "Parses network connection history"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.debug("Started NetworkList Plugin...")

        self._parse_profiles()
        self._parse_signatures()

    def _parse_profiles(self):
        """Parse network profiles"""
        try:
            profiles_key = self.registry_hive.get_key(PROFILES_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find NetworkList Profiles at: {PROFILES_PATH}")
            return

        for subkey in profiles_key.iter_subkeys():
            profile_guid = subkey.name
            subkey_path = f"{PROFILES_PATH}\\{profile_guid}"

            entry = {
                "type": "profile",
                "key_path": subkey_path,
                "profile_guid": profile_guid,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            }

            for value in subkey.iter_values():
                name = value.name
                val = value.value

                if name == "ProfileName":
                    entry["profile_name"] = val
                elif name == "Description":
                    entry["description"] = val
                elif name == "Managed":
                    entry["managed"] = val == 1
                elif name == "Category":
                    # 0 = Public, 1 = Private, 2 = Domain
                    categories = {0: "Public", 1: "Private", 2: "Domain"}
                    entry["category"] = categories.get(val, f"Unknown ({val})")
                elif name == "CategoryType":
                    entry["category_type"] = val
                elif name == "NameType":
                    # 0x06 = Wired, 0x17 = Broadband, 0x47 = Wireless
                    name_types = {0x06: "Wired", 0x17: "Broadband", 0x47: "Wireless"}
                    entry["name_type"] = name_types.get(val, f"Unknown ({val})")
                elif name == "DateCreated":
                    entry["date_created"] = parse_network_date(val)
                elif name == "DateLastConnected":
                    entry["date_last_connected"] = parse_network_date(val)

            self.entries.append(entry)

    def _parse_signatures(self):
        """Parse network signatures (contains MAC addresses)"""
        signature_types = ["Managed", "Unmanaged"]

        for sig_type in signature_types:
            sig_path = f"{SIGNATURES_PATH}\\{sig_type}"
            try:
                sig_key = self.registry_hive.get_key(sig_path)
            except RegistryKeyNotFoundException:
                continue

            for subkey in sig_key.iter_subkeys():
                signature_id = subkey.name
                subkey_path = f"{sig_path}\\{signature_id}"

                entry = {
                    "type": "signature",
                    "signature_type": sig_type.lower(),
                    "key_path": subkey_path,
                    "signature_id": signature_id,
                    "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
                }

                for value in subkey.iter_values():
                    name = value.name
                    val = value.value

                    if name == "ProfileGuid":
                        entry["profile_guid"] = val
                    elif name == "Description":
                        entry["description"] = val
                    elif name == "Source":
                        entry["source"] = val
                    elif name == "DefaultGatewayMac":
                        if isinstance(val, bytes) and len(val) == 6:
                            entry["default_gateway_mac"] = ":".join(f"{b:02X}" for b in val)
                        else:
                            entry["default_gateway_mac_raw"] = val
                    elif name == "DnsSuffix":
                        entry["dns_suffix"] = val
                    elif name == "FirstNetwork":
                        entry["first_network"] = val

                self.entries.append(entry)
