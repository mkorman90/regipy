import logbook

from regipy import RegistryKeyNotFoundException, convert_wintime
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logbook.Logger(__name__)


SAFEBOOT_NETWORK_PATH = r'Control\SafeBoot\Network'
SAFEBOOT_MINIMAL_PATH = r'Control\SafeBoot\Minimal'


class SafeBootConfigurationPlugin(Plugin):
    NAME = 'safeboot_configuration'
    DESCRIPTION = 'Get safeboot configuration'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def _get_safeboot_entries(self, subkey_path):
        entries = []
        for safeboot_network_path in self.registry_hive.get_control_sets(subkey_path):
            control_set_name = safeboot_network_path.split('\\')[1]
            try:
                subkey = self.registry_hive.get_key(safeboot_network_path)
            except RegistryKeyNotFoundException as ex:
                logger.error(ex)
                continue

            for safeboot_network_subkey in subkey.iter_subkeys():
                timestamp = convert_wintime(safeboot_network_subkey.header.last_modified, as_json=self.as_json)
                entries.append({
                    'timestamp': timestamp,
                    'name': safeboot_network_subkey.name,
                    'description': safeboot_network_subkey.get_value(),
                    'control_set_name': control_set_name
                })
        return entries

    def run(self):
        logger.info('Started Safeboot Configuration Plugin...')

        self.entries = {
            'network': self._get_safeboot_entries(SAFEBOOT_NETWORK_PATH),
            'minimal': self._get_safeboot_entries(SAFEBOOT_MINIMAL_PATH)
        }
