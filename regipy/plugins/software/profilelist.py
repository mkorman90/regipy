import pytz
import datetime
import logbook

from regipy.exceptions import RegistryKeyNotFoundException, NoRegistryValuesException
from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list
from regipy.utils import convert_wintime, convert_filetime


logger = logbook.Logger(__name__)

PROFILE_LIST_KEY_PATH = r"\Microsoft\Windows NT\CurrentVersion\ProfileList"

class ProfileListPlugin(Plugin):
    NAME = 'profilelist_plugin'
    DESCRIPTION = 'Parses information about user profiles found in the ProfileList key'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        logger.info('Started profile list plugin...')
        try:
            subkey = self.registry_hive.get_key(PROFILE_LIST_KEY_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(ex)
                
        for profile in subkey.iter_subkeys():
            self.entries.append({
                'last_write': convert_wintime(profile.header.last_modified, as_json=self.as_json),
                'path': profile.get_value('ProfileImagePath'),
                'flags': profile.get_value('Flags'),
                'full_profile': profile.get_value('FullProfile'),
                'state': profile.get_value('State'),
                'sid': profile.name,
                'load_time': convert_filetime(profile.get_value('ProfileLoadTimeLow'), profile.get_value('ProfileLoadTimeHigh')),
                'local_load_time': convert_filetime(profile.get_value('LocalProfileLoadTimeLow'), profile.get_value('LocalProfileLoadTimeHigh'))
            })
