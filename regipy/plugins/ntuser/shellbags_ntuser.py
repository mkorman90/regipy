import logging
from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime
import pyfwsi
import re

logger = logging.getLogger(__name__)

NTUSER_SHELLBAG = '\\Software\\Microsoft\\Windows\\Shell\\BagMRU'
USRCLASS_SHELLBAG = '\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU'
CODEPAGE = 'cp1252'

class ShellBagNtuserPlugin(Plugin):
    NAME = 'shellbag_plugin'
    DESCRIPTION = 'Parse Shellbag items'
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    def _parse_MRU(self,mru_val):
        mru_order_string = ''
        if isinstance(mru_val,bytes):
            mru_val = mru_val[:-4]
            for i in range(0,len(mru_val),4):
                mru_order_string += f'{str(mru_val[i])}-'

            return mru_order_string[:-1]
        else:
            return mru_order_string

    def _get_shell_item_type(self,shell_item):

        if isinstance(shell_item, pyfwsi.volume):
            item_type = "Volume"

        elif isinstance(shell_item, pyfwsi.file_entry):
            item_type = "File Entry"

        elif isinstance(shell_item, pyfwsi.network_location):
            item_type = "Network Location"

        else:
            item_type = 'unknown'

        return item_type

    def _parse_shell_Item_path_segment(self,shell_item):
        """Parses a shell item path segment.
        Args:
          shell_item (pyfwsi.item): shell item.
        Returns:
          str: shell item path segment.
        """
        path_segment = None

        if isinstance(shell_item, pyfwsi.volume):
            if shell_item.name:
                path_segment = shell_item.name
            elif shell_item.identifier:
                path_segment = '{{{0:s}}}'.format(shell_item.identifier)

        elif isinstance(shell_item, pyfwsi.file_entry):
            long_name = ''
            for extension_block in shell_item.extension_blocks:
                if isinstance(extension_block, pyfwsi.file_entry_extension):
                    long_name = extension_block.long_name

            if long_name:
                path_segment = long_name
            elif shell_item.name:
                path_segment = shell_item.name

        elif isinstance(shell_item, pyfwsi.network_location):
            if shell_item.location:
                path_segment = shell_item.location

        if path_segment is None:
            path_segment = '<UNKNOWN: 0x{0:02x}>'.format(shell_item.class_type)

        return path_segment

    def iter_sk(self,key, reg_path, path='root'):

        last_write = convert_wintime(key.header.last_modified, as_json=True)


        mru_val = key.get_value('MRUListEx')
        mru_order = self._parse_MRU(mru_val)

        if key.get_value('NodeSlot'):
            node_slot = str(key.get_value('NodeSlot'))
        else:
            node_slot = ''

        for v in key.iter_values():
            if re.match("\d+", v.name):
                slot = v.name
                byte_stream = v.value
                shell_items = pyfwsi.item_list()
                shell_items.copy_from_byte_stream(byte_stream, ascii_codepage=CODEPAGE)
                for item in shell_items.items:
                    shell_type = self._get_shell_item_type(item)
                    value = self._parse_shell_Item_path_segment(item)
                    path = f'{path}\\{value}'

                    creation_time = ''
                    access_time = ''

                    if len(item.extension_blocks) > 0:
                        for extension_block in item.extension_blocks:
                            if isinstance(extension_block, pyfwsi.file_entry_extension):
                                creation_time = extension_block.get_creation_time().isoformat()
                                access_time = extension_block.get_access_time().isoformat()

                    if hasattr(item,'modification_time'):
                        modification_time = item.get_modification_time().isoformat()
                    else:
                        modification_time = None

                    sk_reg_path = f'{reg_path}\\{v.name}'
                    entry = {'value': value,
                             'slot': slot,
                             'reg_path': sk_reg_path,
                             'node_slot': node_slot,
                             'shell_type': shell_type,
                             'path': path,
                             'creation_time': creation_time,
                             'access_time': access_time,
                             'modification_time': modification_time,
                             'last_write': last_write,
                             'mru_order' : mru_order}

                    self.entries.append(entry)

                    sk = self.registry_hive.get_key(sk_reg_path)
                    self.iter_sk(sk, sk_reg_path, path)






    def run(self):
        try:
            shellbag_ntuser_subkey = self.registry_hive.get_key(NTUSER_SHELLBAG)
            self.iter_sk(shellbag_ntuser_subkey, NTUSER_SHELLBAG)



        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {NTUSER_SHELLBAG}: {ex}')










