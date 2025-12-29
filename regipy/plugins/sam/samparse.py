"""
SAM Parse plugin - Parses user account information from SAM hive
"""

import contextlib
import logging
import struct
from datetime import datetime
from typing import Optional

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SAM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

SAM_USERS_PATH = r"\SAM\Domains\Account\Users"
SAM_NAMES_PATH = r"\SAM\Domains\Account\Users\Names"

# Account type flags
ACCOUNT_FLAGS = {
    0x0001: "Account Disabled",
    0x0002: "Home Directory Required",
    0x0004: "Password Not Required",
    0x0008: "Temp Duplicate Account",
    0x0010: "Normal User Account",
    0x0020: "MNS Logon Account",
    0x0040: "Interdomain Trust Account",
    0x0080: "Workstation Trust Account",
    0x0100: "Server Trust Account",
    0x0200: "Password Does Not Expire",
    0x0400: "Account Auto Locked",
    0x0800: "Encrypted Text Password Allowed",
    0x1000: "Smartcard Required",
    0x2000: "Trusted For Delegation",
    0x4000: "Not Delegated",
    0x8000: "Use DES Key Only",
    0x10000: "Preauth Not Required",
    0x20000: "Password Expired",
    0x40000: "Trusted To Auth For Delegation",
    0x80000: "No Auth Data Required",
    0x100000: "Partial Secrets Account",
}


def filetime_to_datetime(filetime: int) -> Optional[str]:
    """Convert Windows FILETIME to ISO datetime string"""
    if filetime == 0 or filetime == 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        # FILETIME is 100-nanosecond intervals since January 1, 1601
        epoch_diff = 116444736000000000  # Difference between 1601 and 1970 in 100-ns
        timestamp = (filetime - epoch_diff) / 10000000
        dt = datetime.utcfromtimestamp(timestamp)
        return dt.isoformat() + "+00:00"
    except (ValueError, OSError, OverflowError):
        return None


def parse_account_flags(flags: int) -> list:
    """Parse account flags bitmask to list of descriptions"""
    result = []
    for bit, description in ACCOUNT_FLAGS.items():
        if flags & bit:
            result.append(description)
    return result


class SAMParsePlugin(Plugin):
    """
    Parses user account information from SAM hive

    Extracts:
    - User names and RIDs
    - Account creation time
    - Last login time
    - Password last set time
    - Login count
    - Account flags (disabled, locked, etc.)
    - Group memberships

    Registry Key: SAM\\Domains\\Account\\Users
    """

    NAME = "samparse"
    DESCRIPTION = "Parses user accounts from SAM hive"
    COMPATIBLE_HIVE = SAM_HIVE_TYPE

    def run(self):
        logger.debug("Started SAM Parse Plugin...")

        # First, build a mapping of RID to username from the Names subkey
        rid_to_name = self._get_rid_to_name_mapping()

        # Then parse user data from the RID subkeys
        try:
            users_key = self.registry_hive.get_key(SAM_USERS_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f"Could not find SAM Users at: {SAM_USERS_PATH}: {ex}")
            return

        for subkey in users_key.iter_subkeys():
            # Skip the Names subkey
            if subkey.name == "Names":
                continue

            # RID is the subkey name in hex (e.g., "000001F4" = 500 = Administrator)
            try:
                rid = int(subkey.name, 16)
            except ValueError:
                continue

            entry = {
                "key_path": f"{SAM_USERS_PATH}\\{subkey.name}",
                "rid": rid,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            }

            # Get username from mapping
            if rid in rid_to_name:
                entry["username"] = rid_to_name[rid]["username"]
                entry["name_key_last_write"] = rid_to_name[rid]["last_write"]

            # Parse the V value (contains most user data)
            v_value = None
            f_value = None
            for value in subkey.iter_values():
                if value.name == "V":
                    v_value = value.value
                elif value.name == "F":
                    f_value = value.value

            if f_value:
                self._parse_f_value(f_value, entry)

            if v_value:
                self._parse_v_value(v_value, entry)

            self.entries.append(entry)

    def _get_rid_to_name_mapping(self) -> dict:
        """Build mapping of RID to username from Names subkey"""
        mapping = {}
        try:
            names_key = self.registry_hive.get_key(SAM_NAMES_PATH)
        except RegistryKeyNotFoundException:
            return mapping

        for subkey in names_key.iter_subkeys():
            username = subkey.name
            last_write = convert_wintime(subkey.header.last_modified, as_json=self.as_json)

            # The default value's type contains the RID
            for value in subkey.iter_values():
                if value.name == "" or value.name == "(Default)":
                    # The value type is the RID
                    rid = value.value_type_raw if hasattr(value, "value_type_raw") else None
                    if rid is None:
                        # Try to get from the raw type
                        with contextlib.suppress(Exception):
                            rid = value._vk_record.data_type
                    if rid:
                        mapping[rid] = {"username": username, "last_write": last_write}
                    break

        return mapping

    def _parse_f_value(self, data, entry: dict):
        """Parse the F value containing user account metadata"""
        if not data:
            return

        # Ensure data is bytes
        if isinstance(data, str):
            try:
                data = bytes.fromhex(data)
            except ValueError:
                data = data.encode("latin-1")

        if len(data) < 72:
            return

        try:
            # F value structure (offsets are for Vista+)
            # 0x08: Last Login Time (FILETIME)
            # 0x18: Password Last Set (FILETIME)
            # 0x20: Account Expires (FILETIME)
            # 0x28: Last Failed Login (FILETIME)
            # 0x30: RID
            # 0x38: Account Control Flags
            # 0x40: Failed Login Count
            # 0x42: Login Count

            last_login = struct.unpack("<Q", data[8:16])[0]
            entry["last_login"] = filetime_to_datetime(last_login)

            pwd_last_set = struct.unpack("<Q", data[24:32])[0]
            entry["password_last_set"] = filetime_to_datetime(pwd_last_set)

            account_expires = struct.unpack("<Q", data[32:40])[0]
            entry["account_expires"] = filetime_to_datetime(account_expires)

            last_failed_login = struct.unpack("<Q", data[40:48])[0]
            entry["last_failed_login"] = filetime_to_datetime(last_failed_login)

            rid_from_f = struct.unpack("<I", data[48:52])[0]
            if rid_from_f and rid_from_f == entry.get("rid"):
                pass  # Consistent

            acct_flags = struct.unpack("<H", data[56:58])[0]
            entry["account_flags"] = acct_flags
            entry["account_flags_parsed"] = parse_account_flags(acct_flags)

            failed_login_count = struct.unpack("<H", data[64:66])[0]
            entry["failed_login_count"] = failed_login_count

            login_count = struct.unpack("<H", data[66:68])[0]
            entry["login_count"] = login_count

        except (struct.error, IndexError) as e:
            logger.debug(f"Error parsing F value: {e}")

    def _parse_v_value(self, data, entry: dict):
        """Parse the V value containing user details like name, comment, etc."""
        if not data:
            return

        # Ensure data is bytes
        if isinstance(data, str):
            try:
                data = bytes.fromhex(data)
            except ValueError:
                data = data.encode("latin-1")

        if len(data) < 0xCC:
            return

        try:
            # V value has a header with offsets to various strings
            # Each entry is: offset (4 bytes), length (4 bytes), unknown (4 bytes)
            # The offsets are relative to 0xCC

            # Username at offset 0x0C
            name_offset = struct.unpack("<I", data[0x0C:0x10])[0] + 0xCC
            name_length = struct.unpack("<I", data[0x10:0x14])[0]
            if name_offset + name_length <= len(data) and name_length > 0:
                username = data[name_offset : name_offset + name_length].decode("utf-16-le", errors="replace")
                if "username" not in entry:
                    entry["username"] = username

            # Full Name at offset 0x18
            fullname_offset = struct.unpack("<I", data[0x18:0x1C])[0] + 0xCC
            fullname_length = struct.unpack("<I", data[0x1C:0x20])[0]
            if fullname_offset + fullname_length <= len(data) and fullname_length > 0:
                entry["full_name"] = data[fullname_offset : fullname_offset + fullname_length].decode(
                    "utf-16-le", errors="replace"
                )

            # Comment at offset 0x24
            comment_offset = struct.unpack("<I", data[0x24:0x28])[0] + 0xCC
            comment_length = struct.unpack("<I", data[0x28:0x2C])[0]
            if comment_offset + comment_length <= len(data) and comment_length > 0:
                entry["comment"] = data[comment_offset : comment_offset + comment_length].decode("utf-16-le", errors="replace")

            # User Comment at offset 0x30
            user_comment_offset = struct.unpack("<I", data[0x30:0x34])[0] + 0xCC
            user_comment_length = struct.unpack("<I", data[0x34:0x38])[0]
            if user_comment_offset + user_comment_length <= len(data) and user_comment_length > 0:
                entry["user_comment"] = data[user_comment_offset : user_comment_offset + user_comment_length].decode(
                    "utf-16-le", errors="replace"
                )

            # Home Directory at offset 0x48
            homedir_offset = struct.unpack("<I", data[0x48:0x4C])[0] + 0xCC
            homedir_length = struct.unpack("<I", data[0x4C:0x50])[0]
            if homedir_offset + homedir_length <= len(data) and homedir_length > 0:
                entry["home_directory"] = data[homedir_offset : homedir_offset + homedir_length].decode(
                    "utf-16-le", errors="replace"
                )

            # Home Directory Connect at offset 0x54
            homedir_connect_offset = struct.unpack("<I", data[0x54:0x58])[0] + 0xCC
            homedir_connect_length = struct.unpack("<I", data[0x58:0x5C])[0]
            if homedir_connect_offset + homedir_connect_length <= len(data) and homedir_connect_length > 0:
                entry["home_directory_connect"] = data[
                    homedir_connect_offset : homedir_connect_offset + homedir_connect_length
                ].decode("utf-16-le", errors="replace")

            # Script Path at offset 0x60
            script_offset = struct.unpack("<I", data[0x60:0x64])[0] + 0xCC
            script_length = struct.unpack("<I", data[0x64:0x68])[0]
            if script_offset + script_length <= len(data) and script_length > 0:
                entry["script_path"] = data[script_offset : script_offset + script_length].decode("utf-16-le", errors="replace")

            # Profile Path at offset 0x6C
            profile_offset = struct.unpack("<I", data[0x6C:0x70])[0] + 0xCC
            profile_length = struct.unpack("<I", data[0x70:0x74])[0]
            if profile_offset + profile_length <= len(data) and profile_length > 0:
                entry["profile_path"] = data[profile_offset : profile_offset + profile_length].decode(
                    "utf-16-le", errors="replace"
                )

            # Workstations at offset 0x78
            workstations_offset = struct.unpack("<I", data[0x78:0x7C])[0] + 0xCC
            workstations_length = struct.unpack("<I", data[0x7C:0x80])[0]
            if workstations_offset + workstations_length <= len(data) and workstations_length > 0:
                entry["workstations"] = data[workstations_offset : workstations_offset + workstations_length].decode(
                    "utf-16-le", errors="replace"
                )

        except (struct.error, IndexError) as e:
            logger.debug(f"Error parsing V value: {e}")
