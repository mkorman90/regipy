import logging

from inflection import underscore

from regipy import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

WINSCP_CONNECTIONS_PATH = r'\Software\Martin Prikryl\WinSCP 2\Sessions'

class WinSCPConnectionsPlugin(Plugin):
    NAME = 'winscp_connections'
    DESCRIPTION = 'Retrieve list of WinSCP connections'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def _get_winscp_connections(self, subkey_path):
        try:
            sessions_sk = self.registry_hive.get_key(subkey_path)
        except RegistryKeyNotFoundException as ex:
            logger.error(ex)
            return

        for winscp_connection in sessions_sk.iter_subkeys():
            values = {underscore(x.name): x.value for x in
                      winscp_connection.iter_values(as_json=self.as_json)} if winscp_connection.values_count else {}
            self.entries.append({
                'timestamp': convert_wintime(winscp_connection.header.last_modified, as_json=self.as_json),
                'hive_name': 'HKEY_CURRENT_USER',
                'key_path': fr'HKEY_CURRENT_USER{subkey_path}\{winscp_connection.name}',
                **values
            })

    def run(self):
        self._get_winscp_connections(WINSCP_CONNECTIONS_PATH)

