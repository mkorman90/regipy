import logging
from datetime import datetime
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)


SPP_CLIENT_PATH = r"\Microsoft\Windows NT\CurrentVersion\SPP\Clients"
value_list = "{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}"


class SppClientsPlugin(Plugin):
    NAME = "spp_clients_plugin"
    DESCRIPTION = "Determines volumes monitored by VSS"
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SOFTWARE_HIVE_TYPE

    def run(self):
        logger.info("Started spp_clients Plugin...")

        try:
            key = self.registry_hive.get_key(SPP_CLIENT_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f"Could not find {self.NAME} subkey at {SPP_CLIENT_PATH}: {ex}")
            return None

        ts: datetime = convert_wintime(key.header.last_modified, as_json=False)  # type: ignore[assignment]
        self.entries: dict[str, Any] = {SPP_CLIENT_PATH: {"last_write": ts.isoformat()}}  # type: ignore[override]

        for val in key.iter_values():
            if val.name in value_list:
                aux_list = []
                for value in val.value:
                    aux_list.append(value.replace("%3A", ":"))
                self.entries[SPP_CLIENT_PATH][val.name] = aux_list
