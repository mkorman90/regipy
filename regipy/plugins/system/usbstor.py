
import logging

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import SYSTEM_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

USBSTOR_KEY_PATH = r'Enum\USBSTOR'
DISK_GUID_PATH = r'Device Parameters\Partmgr'
PROPERTIES_NAME_GUID = r'{540b947e-8b40-45bc-a8a2-6a0b894cbda2}'
PROPERTIES_DATES_GUID = r'{83da6326-97a6-4088-9453-a1923f573b29}'
DEVICE_NAME_KEY = '0004'
FIRST_INSTALLED_TIME_KEY = '0065'
LAST_CONNECTED_TIME_KEY = '0066'
LAST_REMOVED_TIME_KEY = '0067'
LAST_INSTALLED_TIME_KEY = '0064'


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
                        manufacturer, title, version = None, None, None

                    for serial_subkey in usbstor_drive.iter_subkeys():
                        timestamp = convert_wintime(serial_subkey.header.last_modified, as_json=self.as_json)
                        serial_number = serial_subkey.name

                        try:
                            device_guid_key = self.registry_hive.get_key(
                                rf'{subkey_path}\{usbstor_drive.name}\{serial_number}\{DISK_GUID_PATH}'
                            )
                            disk_guid = device_guid_key.get_value('DiskId')
                        except RegistryKeyNotFoundException:
                            disk_guid = None

                        properties_subkey = serial_subkey.get_subkey('Properties')
                        if not properties_subkey:
                            device_name, first_installed_time, last_connected_time, last_removed_time, \
                                last_installed_time = None, None, None, None, None
                        else:
                            try:
                                device_name_guid_key = properties_subkey.get_subkey(PROPERTIES_NAME_GUID)
                                device_name_key = device_name_guid_key.get_subkey(DEVICE_NAME_KEY)
                                device_name = device_name_key.get_value()
                            except RegistryKeyNotFoundException:
                                device_name = None

                            first_installed_time, last_connected_time, last_removed_time, \
                                last_installed_time = None, None, None, None

                            dates_subkey = properties_subkey.get_subkey(PROPERTIES_DATES_GUID, raise_on_missing=False)
                            if dates_subkey:
                                first_installed_key = dates_subkey.get_subkey(FIRST_INSTALLED_TIME_KEY)
                                if first_installed_key:
                                    first_installed_time = first_installed_key.get_value(as_json=self.as_json)

                                last_connected_key = dates_subkey.get_subkey(LAST_CONNECTED_TIME_KEY,
                                                                             raise_on_missing=False)
                                if last_connected_key:
                                    last_connected_time = last_connected_key.get_value(as_json=self.as_json)

                                last_removed_key = dates_subkey.get_subkey(LAST_REMOVED_TIME_KEY,
                                                                           raise_on_missing=False)
                                if last_removed_key:
                                    last_removed_time = last_removed_key.get_value(as_json=self.as_json)

                                last_installed_key = dates_subkey.get_subkey(LAST_INSTALLED_TIME_KEY,
                                                                             raise_on_missing=False)
                                if last_installed_key:
                                    last_installed_time = last_installed_key.get_value(as_json=self.as_json)

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