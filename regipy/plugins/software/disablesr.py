import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)


SYS_RESTORE_PATH = r"\Microsoft\Windows NT\CurrentVersion\SystemRestore"
value_list = "DisableSR"


class DisableSRPlugin(Plugin):
    NAME = "disablesr_plugin"
    DESCRIPTION = "Gets the value that turns System Restore either on or off"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SOFTWARE_HIVE_TYPE

    def run(self):
        logger.info("Started disablesr Plugin...")

        try:
            key = self.registry_hive.get_key(SYS_RESTORE_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f"Could not find {self.NAME} subkey at {SYS_RESTORE_PATH}: {ex}")
            return None

        self.entries = {SYS_RESTORE_PATH: {"last_write": convert_wintime(key.header.last_modified).isoformat()}}

        for val in key.iter_values():
            if val.name in value_list:
                self.entries[SYS_RESTORE_PATH][val.name] = val.value
