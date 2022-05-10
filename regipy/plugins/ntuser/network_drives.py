
import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

NETWORK_DRIVES = r'\Network'


class NetworkDrivesPlugin(Plugin):
    NAME = 'network_drives_plugin'
    DESCRIPTION = "Parse the user's mapped network drives"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            network_drives = self.registry_hive.get_key(NETWORK_DRIVES)
            for mapped_drive in network_drives.iter_subkeys():
                timestamp = convert_wintime(mapped_drive.header.last_modified, as_json=self.as_json)
                self.entries.append({
                    'last_write': timestamp,
                    'drive_letter': mapped_drive.name,
                    'network_path': mapped_drive.get_value('RemotePath')
                })

        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {NETWORK_DRIVES}: {ex}')