
import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

USBSTOR_KEY_PATH = r'Enum\USBSTOR'
PROPERTIES_NAME_GUID = r'{540b947e-8b40-45bc-a8a2-6a0b894cbda2}'
PROPERTIES_DATES_GUID = r'{83da6326-97a6-4088-9453-a1923f573b29}'


class USBSTORPlugin(Plugin):
    NAME = 'usbstor_plugin'
    DESCRIPTION = "Parse the connected USB devices history"
    COMPATIBLE_HIVE = SYSTEM_HIVE_TYPE

    def run(self):
        try:
            for subkey_path in self.registry_hive.get_control_sets(USBSTOR_KEY_PATH):
                usbstor_key = self.registry_hive.get_key(subkey_path)
                for usbstor_drive in usbstor_key.iter_subkeys():
                    try:
                        disk, manufacturer, title, version = usbstor_drive.name.split('&')
                    except ValueError:
                        manufacturer = ""
                        title = ""
                        version = ""

                    for serial_subkey in usbstor_drive.iter_subkeys():
                        timestamp = convert_wintime(serial_subkey.header.last_modified, as_json=self.as_json)
                        serial_number = serial_subkey.name

                        device_guid_key = serial_subkey.get_subkey('Device Parameters').get_subkey('Partmgr')
                        disk_guid = device_guid_key.get_value('DiskId')

                        properties_subkey = serial_subkey.get_subkey('Properties')
                        device_name_key = properties_subkey.get_subkey(PROPERTIES_NAME_GUID).get_subkey('0004')
                        device_name = device_name_key.get_value().encode('utf8')

                        dates_subkey = properties_subkey.get_subkey(PROPERTIES_DATES_GUID)
                        first_installed_key = dates_subkey.get_subkey('0065')
                        import pdb;pdb.set_trace()
                        first_installed_time = convert_wintime(first_installed_key.get_value(), as_json=self.as_json)

                        last_connected_key = dates_subkey.get_subkey('0066')
                        last_connected_time = convert_wintime(last_connected_key.get_value(), as_json=self.as_json)

                        last_removed_key = dates_subkey.get_subkey('0067')
                        last_removed_time = convert_wintime(last_removed_key.get_value(), as_json=self.as_json)

                        last_installed_key = dates_subkey.get_subkey('0064')
                        last_installed_time = convert_wintime(last_installed_key.get_value(), as_json=self.as_json)

                        self.entries.append({
                            'last_write': timestamp,
                            'last_connected': last_connected_time,
                            'last_removed': last_removed_time,
                            'first_installed': first_installed_time,
                            'last_installed': last_installed_time,
                            'serial_number': serial_number,
                            'device_name': device_name,
                            'disk_guid': disk_guid,
                            'manufacturer': manufacturer,
                            'version': version,
                            'title': title,
                        })

        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {USBSTOR_KEY_PATH}: {ex}')