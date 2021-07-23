"""
Windows machine local SID extractor plugin
"""

import logging

from regipy.hive_types import SAM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.structs import SID
from regipy.utils import convert_wintime
from regipy.security_utils import convert_sid

logger = logging.getLogger(__name__)

ACCOUNT_PATH = r"\SAM\Domains\Account"


class LocalSidPlugin(Plugin):
    """
    Windows machine local SID extractor
    """

    NAME = "local_sid"
    DESCRIPTION = "Get the machine local SID"
    COMPATIBLE_HIVE = SAM_HIVE_TYPE

    def run(self) -> None:
        logger.info("Started Machine Local SID Plugin...")

        account_key = self.registry_hive.get_key(ACCOUNT_PATH)

        # A computer's SID is stored in the SECURITY hive
        # under 'SECURITY\SAM\Domains\Account'.
        # This key has a value named 'F' and a value named 'V'.
        v_value = account_key.get_value("V")

        # The 'V' value is a binary value that has the computer SID embedded
        # within it at the end of its data.
        sid_value = v_value[-24:]

        parsed_sid = SID.parse(sid_value)

        self.entries.append(
            {
                "machine_sid": convert_sid(parsed_sid),
                "timestamp": convert_wintime(
                    account_key.header.last_modified, as_json=self.as_json
                ),
            }
        )
