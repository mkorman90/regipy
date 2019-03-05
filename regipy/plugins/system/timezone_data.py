import logbook

from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin


logger = logbook.Logger(__name__)

TZ_DATA_PATH = r'Control\TimeZoneInformation'


class TimezoneDataPlugin(Plugin):
    NAME = 'timezone_data'
    DESCRIPTION = 'Get timezone data'
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        result = {}
        tzdata_subkeys = self.registry_hive.get_control_sets(TZ_DATA_PATH)
        for tzdata_subkey in tzdata_subkeys:
            tzdata = self.registry_hive.get_key(tzdata_subkey)
            result[tzdata_subkey] = [x for x in tzdata.iter_values(as_json=self.as_json)]
        return result



