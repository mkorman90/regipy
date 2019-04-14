import logbook
from inflection import underscore

from regipy import RegistryKeyNotFoundException, convert_wintime
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin

logger = logbook.Logger(__name__)


TYPED_URLS_KEY_PATH = r'\Software\Microsoft\Internet Explorer\TypedURLs'


class TypedUrlsPlugin(Plugin):
    NAME = 'typed_urls'
    DESCRIPTION = 'Retrieve the typed URLs from IE history'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            subkey = self.registry_hive.get_key(TYPED_URLS_KEY_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {TYPED_URLS_KEY_PATH}: {ex}')
            return None

        self.entries = {
            'last_write': convert_wintime(subkey.header.last_modified, as_json=self.as_json),
            'entries': [{underscore(x.name): x.value} for x in subkey.iter_values(as_json=self.as_json)]
        }
