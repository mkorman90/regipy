import logging

from regipy import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

INSTALLED_SOFTWARE_PATH = r"\Software\Microsoft\Windows\CurrentVersion\Uninstall"


class InstalledProgramsNTUserPlugin(Plugin):
    NAME = "installed_programs_ntuser"
    DESCRIPTION = "Retrieve list of installed programs and their install date from the NTUSER Hive"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def _get_installed_software(self, subkey_path):
        try:
            uninstall_sk = self.registry_hive.get_key(subkey_path)
        except RegistryKeyNotFoundException as ex:
            logger.error(ex)
            return

        for installed_program in uninstall_sk.iter_subkeys():
            values = (
                {x.name: x.value for x in installed_program.iter_values(as_json=self.as_json)}
                if installed_program.values_count
                else {}
            )
            self.entries.append(
                {
                    "service_name": installed_program.name,
                    "timestamp": convert_wintime(installed_program.header.last_modified, as_json=self.as_json),
                    "registry_path": subkey_path,
                    **values,
                }
            )

    def run(self):
        self._get_installed_software(INSTALLED_SOFTWARE_PATH)
