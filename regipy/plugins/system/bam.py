import logging

from construct import Int64ul

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

BAM_PATH = [r"Services\bam\UserSettings", r"Services\bam\state\UserSettings"]


class BAMPlugin(Plugin):
    NAME = "background_activity_moderator"
    DESCRIPTION = "Get the computer name"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.debug("Started Computer Name Plugin...")

        for path in BAM_PATH:
            try:
                for subkey_path in self.registry_hive.get_control_sets(path):
                    subkey = self.registry_hive.get_key(subkey_path)
                    for sid_subkey in subkey.iter_subkeys():
                        sid = sid_subkey.name
                        logger.debug(f"Parsing BAM for {sid}")
                        sequence_number = None
                        version = None
                        entries = []

                        for value in sid_subkey.get_values(trim_values=self.trim_values):
                            if value.name == "SequenceNumber":
                                sequence_number = value.value
                            elif value.name == "Version":
                                version = value.value
                            else:
                                entries.append(
                                    {
                                        "executable": value.name,
                                        "timestamp": convert_wintime(
                                            Int64ul.parse(value.value),
                                            as_json=self.as_json,
                                        ),
                                    }
                                )

                        self.entries.extend(
                            [
                                {
                                    "sequence_number": sequence_number,
                                    "version": version,
                                    "sid": sid,
                                    "key_path": f"{subkey_path}\\{sid}",
                                    **x,
                                }
                                for x in entries
                            ]
                        )
            except RegistryKeyNotFoundException as ex:
                logger.error(ex)
