import logging

from regipy import RegistryKeyNotFoundException, convert_wintime, NoRegistrySubkeysException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logging.getLogger(__name__)

TSCLIENT_HISTORY_PATH = r'\Software\Microsoft\Terminal Server Client\Servers'


class TSClientPlugin(Plugin):
    NAME = 'terminal_services_history'
    DESCRIPTION = 'Retrieve history of RDP connections'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            tsclient_subkey = self.registry_hive.get_key(TSCLIENT_HISTORY_PATH)
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException) as ex:
            logger.error(ex)
            return

        for server in tsclient_subkey.iter_subkeys():
            self.entries.append({
                'server': server.name,
                'last_connection': convert_wintime(server.header.last_modified, as_json=self.as_json),
                'username_hint': server.get_value('UsernameHint')
            })
