import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)


PROCESSOR_PATH = r"Control\CrashControl"
crash_items = ("CrashDumpEnabled", "DumpFile", "MinidumpDir", "LogEvent")
dump_enabled = {
    "0": "None",
    "1": "Complete memory dump",
    "2": "Kernel memory dump",
    "3": "Small memory dump (64 KB)",
    "7": "Automatic memory dump",
}


class CrashDumpPlugin(Plugin):
    NAME = "crash_dump"
    DESCRIPTION = "Get crash control information"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = {}
        architecture_subkeys = self.registry_hive.get_control_sets(PROCESSOR_PATH)
        for architecture_subkey in architecture_subkeys:
            try:
                architecture = self.registry_hive.get_key(architecture_subkey)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Could not find {self.NAME} subkey at {architecture_subkey}: {ex}")
                continue
            self.entries[architecture_subkey] = {"last_write": convert_wintime(architecture.header.last_modified).isoformat()}
            for val in architecture.iter_values():
                if val.name in crash_items:
                    self.entries[architecture_subkey][val.name] = val.value
                if val.name == "CrashDumpEnabled":
                    self.entries[architecture_subkey]["CrashDumpEnabledStr"] = dump_enabled.get(str(val.value), "")
