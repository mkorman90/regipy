import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)


LAST_ACCESS_PATH = r"Control\FileSystem"
crash_items = ("NtfsDisableLastAccessUpdate", "NtfsDisableLastAccessUpdate")
last_acc = {
    "80000000": "(User Managed, Updates Enabled)",
    "80000001": "(User Managed, Updates Disabled)",
    "80000002": "(System Managed, Updates Enabled)",
    "80000003": "(System Managed, Updates Disabled)",
}


class DisableLastAccessPlugin(Plugin):
    NAME = "disable_last_access"
    DESCRIPTION = "Get NTFSDisableLastAccessUpdate value"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SYSTEM_HIVE_TYPE

    def run(self):
        self.entries = {}
        access_subkeys = self.registry_hive.get_control_sets(LAST_ACCESS_PATH)
        for access_subkey in access_subkeys:
            try:
                access = self.registry_hive.get_key(access_subkey)
            except RegistryKeyNotFoundException as ex:
                logger.error(f"Could not find {self.NAME} subkey at {access_subkey}: {ex}")
                continue
            self.entries[access_subkey] = {"last_write": convert_wintime(access.header.last_modified).isoformat()}
            for val in access.iter_values():
                if val.name in crash_items:
                    self.entries[access_subkey][val.name] = f"{val.value:0x}"
                    self.entries[access_subkey][f"{val.name}Str"] = last_acc.get(f"{val.value:0x}", "")
