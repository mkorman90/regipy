import logging
from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import USRCLASS_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime
from regipy.constants import KNOWN_GUIDS
import re

logger = logging.getLogger(__name__)

USRCLASS_SHELLBAG = '\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU'
CODEPAGE = 'cp1252'


class ShellBagUsrclassPlugin(Plugin):
    NAME = 'usrclass_shellbag_plugin'
    DESCRIPTION = 'Parse USRCLASS Shellbag items'
    COMPATIBLE_HIVE = USRCLASS_HIVE_TYPE

    @staticmethod
    def _parse_mru(mru_val):
        mru_order_string = ''
        if isinstance(mru_val, bytes):
            mru_val = mru_val[:-4]
            for i in range(0, len(mru_val), 4):
                mru_order_string += f'{str(mru_val[i])}-'

            return mru_order_string[:-1]
        else:
            return mru_order_string

    @staticmethod
    def _get_shell_item_type(shell_item):
        try:
            import pyfwsi
        except ModuleNotFoundError as ex:
            logger.exception(f"Plugin `shellbag_plugin` has missing modules, install regipy using"
                             f" `pip install regipy[full]` in order to install plugin dependencies. "
                             f"This might take some time... ")
            raise ex

        if isinstance(shell_item, pyfwsi.volume):
            item_type = "Volume"

        elif isinstance(shell_item, pyfwsi.file_entry):
            item_type = "Directory"

        elif isinstance(shell_item, pyfwsi.network_location):
            item_type = "Network Location"

        elif isinstance(shell_item, pyfwsi.root_folder):
            item_type = "Root Folder"

        else:
            item_type = 'unknown'

        return item_type

    @staticmethod
    def _parse_shell_item_path_segment(self, shell_item):
        """Parses a shell item path segment.
        Args:
          shell_item (pyfwsi.item): shell item.
        Returns:
          str: shell item path segment.
        """

        try:
            import pyfwsi
        except ModuleNotFoundError as ex:
            logger.exception(f"Plugin `shellbag_plugin` has missing modules, install regipy using"
                             f" `pip install regipy[full]` in order to install plugin dependencies. "
                             f"This might take some time... ")
            raise ex

        path_segment = None

        if isinstance(shell_item, pyfwsi.volume):
            if shell_item.name:
                path_segment = shell_item.name
            elif shell_item.identifier:
                if shell_item.identifier in KNOWN_GUIDS:
                    path_segment = KNOWN_GUIDS[shell_item.identifier]
                else:
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

        elif isinstance(shell_item, pyfwsi.root_folder):
            if shell_item.shell_folder_identifier in KNOWN_GUIDS:
                path_segment = KNOWN_GUIDS[shell_item.shell_folder_identifier]
            elif hasattr(shell_item, 'identifier') and shell_item.identifier in KNOWN_GUIDS:
                path_segment = KNOWN_GUIDS[shell_item.identifier]
            else:
                path_segment = '{{{0:s}}}'.format(shell_item.shell_folder_identifier)

        if path_segment is None:
            path_segment = '<UNKNOWN: 0x{0:02x}>'.format(shell_item.class_type)

        return path_segment

    def iter_sk(self, key, reg_path, base_path='', path=''):
        try:
            import pyfwsi
        except ModuleNotFoundError as ex:
            logger.exception(f"Plugin `shellbag_plugin` has missing modules, install regipy using"
                             f" `pip install regipy[full]` in order to install plugin dependencies. "
                             f"This might take some time... ")
            raise ex

        last_write = convert_wintime(key.header.last_modified, as_json=True)

        mru_val = key.get_value('MRUListEx')
        mru_order = self._parse_mru(mru_val)
        base_path = path

        if key.get_value('NodeSlot'):
            node_slot = str(key.get_value('NodeSlot'))
        else:
            node_slot = ''

        for v in key.iter_values(trim_values=False):
            if re.match("\d+", v.name):
                slot = v.name
                byte_stream = v.value
                shell_items = pyfwsi.item_list()
                shell_items.copy_from_byte_stream(byte_stream, ascii_codepage=CODEPAGE)
                for item in shell_items.items:
                    shell_type = self._get_shell_item_type(item)
                    value = self._parse_shell_item_path_segment(self, item)
                    if not path:
                        path = value
                        base_path = ''
                    else:
                        path += f'\\{value}'

                    creation_time = None
                    access_time = None
                    modification_time = None

                    if len(item.extension_blocks) > 0:
                        for extension_block in item.extension_blocks:
                            if isinstance(extension_block, pyfwsi.file_entry_extension):
                                try:
                                    creation_time = extension_block.get_creation_time()
                                    if self.as_json:
                                        creation_time = creation_time.isoformat()
                                except OSError:
                                    logger.exception(f'Malformed creation time for {path}')
                                try:
                                    access_time = extension_block.get_access_time()
                                    if self.as_json:
                                        access_time = access_time.isoformat()
                                except OSError:
                                    logger.exception(f'Malformed access time for {path}')

                    try:
                        if hasattr(item, 'modification_time'):
                            modification_time = item.get_modification_time()
                            if self.as_json:
                                modification_time = modification_time.isoformat()
                    except OSError:
                        logger.exception(f'Malformed modification time for {path}')

                    value_name = v.name
                    mru_order_location = mru_order.split('-').index(value_name)
                    entry = {'value': value,
                             'slot': slot,
                             'reg_path': reg_path,
                             'value_name': value_name,
                             'node_slot': node_slot,
                             'shell_type': shell_type,
                             'path': path,
                             'creation_time': creation_time,
                             'access_time': access_time,
                             'modification_time': modification_time,
                             'last_write': last_write,
                             'mru_order': mru_order,
                             'mru_order_location': mru_order_location,
                             }

                    self.entries.append(entry)
                    sk_reg_path = f'{reg_path}\\{value_name}'
                    sk = self.registry_hive.get_key(sk_reg_path)
                    self.iter_sk(sk, sk_reg_path, base_path, path)
                    path = base_path

    def run(self):

        try:
            import pyfwsi
        except ModuleNotFoundError as ex:
            logger.exception(f"Plugin `shellbag_plugin` has missing modules, install regipy using"
                             f" `pip install regipy[full]` in order to install plugin dependencies. "
                             f"This might take some time... ")
            raise ex

        try:
            shellbag_usrclass_subkey = self.registry_hive.get_key(USRCLASS_SHELLBAG)
            self.iter_sk(shellbag_usrclass_subkey, USRCLASS_SHELLBAG)
        except RegistryKeyNotFoundException as ex:
            logger.error(f'Could not find {self.NAME} plugin data at: {USRCLASS_SHELLBAG}: {ex}')