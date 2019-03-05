import logbook

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin


logger = logbook.Logger(__name__)

SELECT = r'\Select'


class ActiveControlSetPlugin(Plugin):
    NAME = 'active_control_set'
    DESCRIPTION = 'Get information on SYSTEM hive control sets'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        subkey = self.registry_hive.get_key(SELECT)
        return [x for x in subkey.iter_values(as_json=self.as_json)]



