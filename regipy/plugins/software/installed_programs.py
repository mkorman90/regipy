import logbook

from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list, convert_wintime

logger = logbook.Logger(__name__)

INSTALLED_SOFTWARE_PATH = r'\Microsoft\Windows\CurrentVersion\Uninstall'


class InstalledSoftwarePlugin(Plugin):
    NAME = 'installed_Software'
    DESCRIPTION = 'Retrieve list of installed programs and their install date'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        installed_programs = []
        uninstall_sk = self.registry_hive.get_key(INSTALLED_SOFTWARE_PATH)
        for installed_program in uninstall_sk.iter_subkeys():
            values = {x['name']: x['value'] for x in
                      installed_program.iter_values(as_json=self.as_json)} if installed_program.values_count else {}
            installed_programs.append({
                'service_name': installed_program.name,
                'timestamp': convert_wintime(installed_program.header.last_modified, as_json=self.as_json),
                **values

            })
        return installed_programs
