import logbook

from regipy import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logbook.Logger(__name__)

TSCLIENT_HISTORY_PATH = r'\SOFTWARE\Microsoft\Terminal Server Client'


class TSClientPlugin(Plugin):
    NAME = 'terminal_services_history'
    DESCRIPTION = 'Retrieve history of RDP connections'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            tsclient_subkey = self.registry_hive.get_key(TSCLIENT_HISTORY_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(ex)
            return

        # TODO: Get a sample with this content


