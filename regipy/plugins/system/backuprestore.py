import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)


BACKUPRESTORE_PATH = [
    r"Control\BackupRestore\FilesNotToSnapshot",
    r"Control\BackupRestore\FilesNotToBackup",
    r"Control\BackupRestore\KeysNotToRestore",
]


class BackupRestorePlugin(Plugin):
    NAME = "backuprestore_plugin"
    DESCRIPTION = "Gets the contents of the FilesNotToSnapshot, KeysNotToRestore, and FilesNotToBackup keys"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = {}
        for br_path in BACKUPRESTORE_PATH:
            br_subkeys = self.registry_hive.get_control_sets(br_path)
            for br_subkey in br_subkeys:
                try:
                    backuprestore = self.registry_hive.get_key(br_subkey)
                except RegistryKeyNotFoundException as ex:
                    logger.error(f"Could not find {self.NAME} subkey at {br_subkey}: {ex}")
                    continue
                self.entries[br_subkey] = {"last_write": convert_wintime(backuprestore.header.last_modified).isoformat()}
                for val in backuprestore.iter_values():
                    self.entries[br_subkey][val.name] = val.value
