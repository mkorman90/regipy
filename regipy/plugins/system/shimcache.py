import logbook

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.plugins.system.external.ShimCacheParser import get_shimcache_entries

logger = logbook.Logger(__name__)

COMPUTER_NAME_PATH = r'Control\Session Manager'


class ShimCachePlugin(Plugin):
    NAME = 'shimcache'
    DESCRIPTION = 'Parse Shimcache artifact'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.info('Started Shim Cache Plugin...')

        shimcaches = []
        for subkey_path in self.registry_hive.get_control_sets(COMPUTER_NAME_PATH):
            appcompat_cache = self.registry_hive.get_key(subkey_path).get_key('AppCompatCache')
            shimcache = appcompat_cache.get_value('AppCompatCache')
            if shimcache:
                for entry in get_shimcache_entries(shimcache, as_json=self.as_json):
                    shimcaches.append(entry)
        return shimcaches
