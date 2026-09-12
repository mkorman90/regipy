import logging
from datetime import datetime
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_filetime2, convert_wintime

logger = logging.getLogger(__name__)

SHUTDOWN_DATA_PATH = r"Control\Windows"


class ShutdownPlugin(Plugin):
    NAME = "shutdown"
    DESCRIPTION = "Get shutdown data"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self) -> None:
        self.entries: dict[str, Any] = {}  # type: ignore[override]
        shutdown_subkeys = self.registry_hive.get_control_sets(SHUTDOWN_DATA_PATH)
        for shutdown_subkey in shutdown_subkeys:
            try:
                shutdown = self.registry_hive.get_key(shutdown_subkey)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Could not find {self.NAME} subkey at {shutdown_subkey}: {ex}")
                continue
            ts: datetime = convert_wintime(shutdown.header.last_modified)  # type: ignore[assignment]
            self.entries[shutdown_subkey] = {"last_write": ts.isoformat()}
            for val in shutdown.iter_values():
                if val.name == "ShutdownTime":
                    self.entries[shutdown_subkey]["date"] = convert_filetime2(val.value)
