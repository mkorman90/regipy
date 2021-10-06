import logging

from regipy.exceptions import RegistryValueNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

WDIGEST_PATH = r'Control\SecurityProviders\WDigest'


class WDIGESTPlugin(Plugin):
    NAME = 'wdigest'
    DESCRIPTION = 'Get WDIGEST configuration'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.info('Started WDIGEST Plugin...')
        for subkey_path in self.registry_hive.get_control_sets(WDIGEST_PATH):
            subkey = self.registry_hive.get_key(subkey_path)

            try:
                self.entries.append({
                    'subkey': subkey_path,
                    'use_logon_credential': subkey.get_value('UseLogonCredential', as_json=self.as_json),
                    'timestamp': convert_wintime(subkey.header.last_modified, as_json=self.as_json)
                })
            except RegistryValueNotFoundException as ex:
                continue
