import logging
import re
from datetime import datetime, timezone

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logging.getLogger(__name__)


WIN_VER_PATH = r"\Setup"
os_list = [
    "ProductName",
    "ReleaseID",
    "CSDVersion",
    "CurrentVersion",
    "CurrentBuild",
    "CurrentBuildNumber",
    "InstallationType",
    "EditionID",
    "ProductName",
    "ProductId",
    "BuildLab",
    "BuildLabEx",
    "CompositionEditionID",
    "RegisteredOrganization",
    "RegisteredOwner",
    "InstallDate",
]


class PreviousWinVersionPlugin(Plugin):
    NAME = "previous_winver_plugin"
    DESCRIPTION = "Get previous relevant OS information"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def can_run(self):
        return self.registry_hive.hive_type == SYSTEM_HIVE_TYPE

    def run(self):
        logger.info("Started winver Plugin...")

        try:
            key = self.registry_hive.get_key(WIN_VER_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f"Could not find {self.NAME} subkey at {WIN_VER_PATH}: {ex}")
            return None

        for sk in key.iter_subkeys():
            if sk.name.startswith("Source OS"):
                old_date = re.search(
                    r"Updated on (\d{1,2})/(\d{1,2})/(\d{4}) (\d{2}):(\d{2}):(\d{2})",
                    sk.name,
                )
                dt = datetime(
                    int(old_date.group(3)),
                    int(old_date.group(1)),
                    int(old_date.group(2)),
                    int(old_date.group(4)),
                    int(old_date.group(5)),
                    int(old_date.group(6)),
                ).strftime("%Y-%m-%d %H:%M:%S")
                temp_dict = {"key": f"\\{key.name}\\{sk.name}"}
                temp_dict["update_date"] = dt
                for val in sk.iter_values():
                    if val.name in os_list:
                        if val.name == "InstallDate":
                            temp_dict[val.name] = datetime.fromtimestamp(val.value, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        else:
                            temp_dict[val.name] = val.value
                self.entries.append(temp_dict)
