"""
Windows machine domain SID extractor plugin
"""

import logging

from regipy.hive_types import SECURITY_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime, decode_binary_sid

logger = logging.getLogger(__name__)

DOMAIN_SID_PATH = r"\Policy\PolMachineAccountS"


class DomainSidPlugin(Plugin):
    """
    Windows machine domain SID extractor
    """

    NAME = "domain_sid"
    DESCRIPTION = "Get the machine domain SID"
    COMPATIBLE_HIVE = SECURITY_HIVE_TYPE

    def run(self) -> None:
        logger.info("Started Machine Domain SID Plugin...")

        sid_key = self.registry_hive.get_key(DOMAIN_SID_PATH)
        sid_value = sid_key.get_value()

        # The default key value is 0x00000000 (REG_DWORD) when
        # the Windows machine is not in an AD domain.
        # Otherwise, it contains the domain machine SID data
        # in the standard binary format (REG_BINARY).
        if not isinstance(sid_value, bytes):
            return

        self.entries.append(
            {
                "domain_sid": decode_binary_sid(sid_value, strip_rid=True),
                "machine_sid": decode_binary_sid(sid_value),
                "timestamp": convert_wintime(
                    sid_key.header.last_modified, as_json=self.as_json
                ),
            }
        )
