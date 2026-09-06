import logging
from datetime import datetime
from typing import Any

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)


PROCESSOR_PATH = r"Control\Nls\CodePage"
crash_items = "ACP"


class CodepagePlugin(Plugin):
    NAME = "codepage"
    DESCRIPTION = "Get codepage value"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SYSTEM_HIVE_TYPE

    def run(self) -> None:
        self.entries: dict[str, Any] = {}  # type: ignore[override]
        codepage_subkeys = self.registry_hive.get_control_sets(PROCESSOR_PATH)
        for codepage_subkey in codepage_subkeys:
            try:
                codepage = self.registry_hive.get_key(codepage_subkey)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Could not find {self.NAME} subkey at {codepage_subkey}: {ex}")
                continue
            ts: datetime = convert_wintime(codepage.header.last_modified)  # type: ignore[assignment]
            self.entries[codepage_subkey] = {"last_write": ts.isoformat()}
            for val in codepage.iter_values():
                if val.name in crash_items:
                    self.entries[codepage_subkey][val.name] = val.value
