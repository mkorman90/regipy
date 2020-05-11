import logbook

from regipy import RegistryKeyNotFoundException, convert_wintime
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logbook.Logger(__name__)

TRACING_PATH = r'\Microsoft\Tracing'
X86_TRACING_PATH = r'\Wow6432Node' + TRACING_PATH


class RASTracingPlugin(Plugin):
    NAME = 'ras_tracing'
    DESCRIPTION = 'Retrieve list of executables using ras'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def _get_installed_software(self, subkey_path):
        try:
            ras_subkey = self.registry_hive.get_key(subkey_path)
        except RegistryKeyNotFoundException as ex:
            logger.error(ex)
            return

        for entry in ras_subkey.iter_subkeys():
            timestamp = convert_wintime(entry.header.last_modified, as_json=self.as_json)
            self.entries.append({
                'key': subkey_path,
                'name': entry.name,
                'timestamp': timestamp
            })

    def run(self):
        self._get_installed_software(TRACING_PATH)
        self._get_installed_software(X86_TRACING_PATH)
