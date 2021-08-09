"""
Windows machine domain name and SID extractor plugin
"""

import logging

from typing import Optional

from regipy.hive_types import SECURITY_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.structs import SID
from regipy.utils import convert_wintime
from regipy.security_utils import convert_sid

logger = logging.getLogger(__name__)

DOMAIN_NAME_PATH = r"\Policy\PolPrDmN"
DOMAIN_SID_PATH = r"\Policy\PolMachineAccountS"


class DomainSidPlugin(Plugin):
    """
    Windows machine domain name and SID extractor
    """

    NAME = "domain_sid"
    DESCRIPTION = "Get the machine domain name and SID"
    COMPATIBLE_HIVE = SECURITY_HIVE_TYPE

    def run(self) -> None:
        logger.info("Started Machine Domain SID Plugin...")

        name_key = self.registry_hive.get_key(DOMAIN_NAME_PATH)

        # Primary Domain Name or Workgroup Name (binary-encoded and length-prefixed)
        name_value = name_key.get_value()

        # Skip UNICODE_STRING struct header and strip trailing \x0000
        domain_name = name_value[8:].decode('utf-16-le', errors='replace').rstrip('\x00')

        sid_key = self.registry_hive.get_key(DOMAIN_SID_PATH)

        # Domain SID value (binary-encoded)
        sid_value = sid_key.get_value()

        domain_sid: Optional[str] = None
        machine_sid: Optional[str] = None

        # The default key value is 0x00000000 (REG_DWORD) when
        # the Windows machine is not in an AD domain.
        # Otherwise, it contains the domain machine SID data
        # in the standard binary format (REG_BINARY).
        if isinstance(sid_value, bytes):
            parsed_sid = SID.parse(sid_value)
            domain_sid = convert_sid(parsed_sid, strip_rid=True)
            machine_sid = convert_sid(parsed_sid)

        self.entries.append(
            {
                "domain_name": domain_name,
                "domain_sid": domain_sid,
                "machine_sid": machine_sid,
                "timestamp": convert_wintime(
                    sid_key.header.last_modified, as_json=self.as_json
                ),
            }
        )
