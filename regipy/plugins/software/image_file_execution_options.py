import logging

from regipy.hive_types import SOFTWARE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import get_subkey_values_from_list, convert_wintime

logger = logging.getLogger(__name__)

IMAGE_FILE_EXECUTION_OPTIONS = r'\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'


class ImageFileExecutionOptions(Plugin):
    NAME = 'image_file_execution_options'
    DESCRIPTION = 'Retrieve image file execution options - a persistence method'
    COMPATIBLE_HIVE = SOFTWARE_HIVE_TYPE

    def run(self):
        image_file_execution_options = self.registry_hive.get_key(IMAGE_FILE_EXECUTION_OPTIONS)
        if image_file_execution_options.subkey_count:
            for subkey in image_file_execution_options.iter_subkeys():
                values = {x.name: x.value for x in
                          subkey.iter_values(as_json=self.as_json)} if subkey.values_count else {}
                self.entries.append({
                    'name': subkey.name,
                    'timestamp': convert_wintime(subkey.header.last_modified, as_json=self.as_json),
                    **values

                })
