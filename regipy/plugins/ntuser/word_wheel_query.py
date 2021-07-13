import binascii
import codecs

import logging

from construct import *

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logging.getLogger(__name__)

WORD_WHEEL_QUERY_KEY_PATH = r'\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery'


class WordWheelQueryPlugin(Plugin):
    NAME = 'word_wheel_query'
    DESCRIPTION = 'Parse the word wheel query artifact'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def run(self):
        try:
            subkey = self.registry_hive.get_key(WORD_WHEEL_QUERY_KEY_PATH)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {WORD_WHEEL_QUERY_KEY_PATH}: {ex}')
            return None

        timestamp = convert_wintime(subkey.header.last_modified, as_json=self.as_json)

        mru_list_order = subkey.get_value('MRUListEx')

        # If this is the value, the list is empty
        if mru_list_order == 0xffffffff:
            return None

        for i, entry_name in enumerate(GreedyRange(Int32ul).parse(mru_list_order)):
            entry_value = subkey.get_value(str(entry_name))

            if not entry_value:
                continue

            self.entries.append({
                'last_write': timestamp,
                'mru_id': entry_name,
                'order': i,
                'name': CString('utf-16').parse(entry_value)
            })
