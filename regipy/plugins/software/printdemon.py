import logging

from regipy import RegistryKeyNotFoundException, convert_wintime
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logging.getLogger(__name__)

PORTS_KEY_PATH = r'\Microsoft\Windows NT\CurrentVersion\Ports'


class PrintDemonPlugin(Plugin):
    NAME = 'print_demon_plugin'
    DESCRIPTION = 'Get list of installed printer ports, as could be taken advantage by cve-2020-1048'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        try:
            subkey = self.registry_hive.get_key(PORTS_KEY_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} subkey at {PORTS_KEY_PATH}: {ex}')
            return None

        last_write = convert_wintime(subkey.header.last_modified).isoformat()
        for port in subkey.iter_values():
            self.entries.append({
                'timestamp': last_write,
                'port_name': port.name,
                'parameters': port.value if isinstance(port.value, int) else port.value.split(',')
            })



