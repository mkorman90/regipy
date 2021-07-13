import logging

from inflection import underscore

from regipy import RegistryKeyNotFoundException, convert_wintime
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logging.getLogger(__name__)

LAST_LOGON_KEY_PATH = r'\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'


class LastLogonPlugin(Plugin):
    NAME = 'last_logon_plugin'
    DESCRIPTION = 'Get the last logged on username'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        try:
            subkey = self.registry_hive.get_key(LAST_LOGON_KEY_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} subkey at {LAST_LOGON_KEY_PATH}: {ex}')
            return None

        self.entries = {
            'last_write': convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            **{underscore(x.name): x.value for x in subkey.iter_values(as_json=self.as_json)}
        }


