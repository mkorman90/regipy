import logbook

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list

logger = logbook.Logger(__name__)


ROUTES_PATH = r'Services\Tcpip\Parameters\PersistentRoutes'


class RoutesPlugin(Plugin):
    NAME = 'routes'
    DESCRIPTION = 'Get list of routes'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        logger.info('Started Routes Plugin...')

        routes_path_list = self.registry_hive.get_control_sets(ROUTES_PATH)

        return get_subkey_values_from_list(self.registry_hive, routes_path_list, as_json=self.as_json)


