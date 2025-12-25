import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logging.getLogger(__name__)


PROCESSOR_PATH = r"Control\Session Manager\Environment"
processor_list = (
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_REVISION",
)


class ProcessorArchitecturePlugin(Plugin):
    NAME = "processor_architecture"
    DESCRIPTION = "Get processor architecture info from the System's environment key"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = {}
        processor_subkeys = self.registry_hive.get_control_sets(PROCESSOR_PATH)
        for processor_subkey in processor_subkeys:
            try:
                processor = self.registry_hive.get_key(processor_subkey)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Could not find {self.NAME} subkey at {processor_subkey}: {ex}")
                continue
            self.entries[processor_subkey] = {}
            for val in processor.iter_values():
                if val.name in processor_list:
                    self.entries[processor_subkey][val.name] = val.value
