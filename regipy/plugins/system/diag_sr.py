import logging
from datetime import datetime
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_filetime2, convert_wintime

logger = logging.getLogger(__name__)


DIAGSR_PATH = r"Services\VSS\Diag\SystemRestore"
crash_items = ("CrashDumpEnabled", "DumpFile", "MinidumpDir", "LogEvent")


class DiagSRPlugin(Plugin):
    NAME = "diag_sr"
    DESCRIPTION = "Get Diag\\SystemRestore values and data"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SYSTEM_HIVE_TYPE

    def run(self) -> None:
        self.entries: dict[str, Any] = {}  # type: ignore[override]
        diagsr_subkeys = self.registry_hive.get_control_sets(DIAGSR_PATH)
        for diagsr_subkey in diagsr_subkeys:
            try:
                diagsr = self.registry_hive.get_key(diagsr_subkey)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Could not find {self.NAME} subkey at {diagsr_subkey}: {ex}")
                continue
            ts: datetime = convert_wintime(diagsr.header.last_modified)  # type: ignore[assignment]
            self.entries[diagsr_subkey] = {"last_write": ts.isoformat()}
            for val in diagsr.iter_values():
                self.entries[diagsr_subkey][val.name] = convert_filetime2(val.value[16:32])
