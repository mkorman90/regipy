"""
PuTTY plugin - Parses PuTTY SSH client configuration and session history
"""

import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.plugins.utils import extract_values
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

PUTTY_SESSIONS_PATH = r"\Software\SimonTatham\PuTTY\Sessions"
PUTTY_SSH_HOST_KEYS_PATH = r"\Software\SimonTatham\PuTTY\SshHostKeys"
PUTTY_JUMPLIST_PATH = r"\Software\SimonTatham\PuTTY\Jumplist"


class PuTTYPlugin(Plugin):
    """
    Parses PuTTY configuration and session history from NTUSER.DAT

    Extracts:
    - Saved sessions with connection details
    - SSH host keys (evidence of connections)
    - Jump list entries
    """

    NAME = "putty"
    DESCRIPTION = "Parses PuTTY sessions and SSH host keys"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        logger.debug("Started PuTTY Plugin...")

        self._parse_sessions()
        self._parse_ssh_host_keys()
        self._parse_jumplist()

    def _parse_sessions(self):
        """Parse saved PuTTY sessions"""
        try:
            sessions_key = self.registry_hive.get_key(PUTTY_SESSIONS_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find PuTTY sessions at: {PUTTY_SESSIONS_PATH}")
            return

        for subkey in sessions_key.iter_subkeys():
            session_name = subkey.name
            # Session names are URL-encoded
            try:
                from urllib.parse import unquote

                decoded_name = unquote(session_name)
            except Exception:
                decoded_name = session_name

            entry = {
                "type": "session",
                "key_path": f"{PUTTY_SESSIONS_PATH}\\{session_name}",
                "session_name": decoded_name,
                "last_write": convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            }

            # Extract required fields
            extract_values(
                subkey,
                {
                    "HostName": "hostname",
                    "PortNumber": "port",
                    "UserName": "username",
                    "Protocol": ("protocol", self._get_protocol_name),
                },
                entry,
            )

            # Extract optional fields (only if non-empty)
            for value in subkey.iter_values():
                name = value.name
                val = value.value

                if name == "ProxyHost" and val:
                    entry["proxy_host"] = val
                elif name == "ProxyPort" and val and val != 0:
                    entry["proxy_port"] = val
                elif name == "ProxyUsername" and val:
                    entry["proxy_username"] = val
                elif name == "PublicKeyFile" and val:
                    entry["public_key_file"] = val
                elif name == "RemoteCommand" and val:
                    entry["remote_command"] = val
                elif name == "PortForwardings" and val:
                    entry["port_forwardings"] = val
                elif name == "LogFileName" and val:
                    entry["log_filename"] = val
                elif name == "WinTitle" and val:
                    entry["window_title"] = val

            self.entries.append(entry)

    def _parse_ssh_host_keys(self):
        """Parse SSH host keys - evidence of connections made"""
        try:
            hostkeys_key = self.registry_hive.get_key(PUTTY_SSH_HOST_KEYS_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find PuTTY SSH host keys at: {PUTTY_SSH_HOST_KEYS_PATH}")
            return

        entry = {
            "type": "ssh_host_keys",
            "key_path": PUTTY_SSH_HOST_KEYS_PATH,
            "last_write": convert_wintime(hostkeys_key.header.last_modified, as_json=self.as_json),
            "hosts": [],
        }

        for value in hostkeys_key.iter_values():
            # Format: algorithm@port:hostname
            # e.g., rsa2@22:192.168.1.1
            host_entry = {"raw_key": value.name}

            if "@" in value.name and ":" in value.name:
                try:
                    algo_port, hostname = value.name.rsplit(":", 1)
                    algo, port = algo_port.split("@", 1)
                    host_entry["algorithm"] = algo
                    host_entry["port"] = int(port)
                    host_entry["hostname"] = hostname
                except Exception:
                    pass

            entry["hosts"].append(host_entry)

        if entry["hosts"]:
            self.entries.append(entry)

    def _parse_jumplist(self):
        """Parse PuTTY jump list entries"""
        try:
            jumplist_key = self.registry_hive.get_key(PUTTY_JUMPLIST_PATH)
        except RegistryKeyNotFoundException:
            logger.debug(f"Could not find PuTTY jumplist at: {PUTTY_JUMPLIST_PATH}")
            return

        entry = {
            "type": "jumplist",
            "key_path": PUTTY_JUMPLIST_PATH,
            "last_write": convert_wintime(jumplist_key.header.last_modified, as_json=self.as_json),
            "recent_sessions": [],
        }

        for value in jumplist_key.iter_values():
            if value.name == "Recent sessions" and value.value:
                # Value is a comma-separated list of session names
                sessions = [s.strip() for s in value.value.split(",") if s.strip()]
                entry["recent_sessions"] = sessions

        if entry["recent_sessions"]:
            self.entries.append(entry)

    @staticmethod
    def _get_protocol_name(protocol_id):
        """Convert protocol ID to name"""
        protocols = {
            0: "Raw",
            1: "Telnet",
            2: "Rlogin",
            3: "SSH",
            4: "Serial",
        }
        return protocols.get(protocol_id, f"Unknown ({protocol_id})")
