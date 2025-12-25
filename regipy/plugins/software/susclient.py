import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)


WIN_VER_PATH = r"\Microsoft\Windows\CurrentVersion\WindowsUpdate"
value_list = ("LastRestorePointSetTime", "SusClientId")


class SusclientPlugin(Plugin):
    NAME = "susclient_plugin"
    DESCRIPTION = "Extracts SusClient* info, including HDD SN"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SOFTWARE_HIVE_TYPE

    def run(self):
        logger.info("Started susclient Plugin...")

        try:
            key = self.registry_hive.get_key(WIN_VER_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f"Could not find {self.NAME} subkey at {WIN_VER_PATH}: {ex}")
            return None

        self.entries = {WIN_VER_PATH: {"last_write": convert_wintime(key.header.last_modified).isoformat()}}

        for val in key.iter_values():
            if val.name == "SusClientIdValidation":
                self.entries[WIN_VER_PATH][val.name] = get_SN(val.value)
            elif val.name in value_list:
                self.entries[WIN_VER_PATH][val.name] = val.value


def get_SN(data):
    offset = int(data[:2], 16)
    length = int(data[4:6], 16)
    return bytes.fromhex(data[2 * offset : 2 * (length + offset)]).decode("utf-16le")
