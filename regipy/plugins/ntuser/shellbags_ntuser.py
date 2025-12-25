import logging
from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import NTUSER_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime
from regipy.constants import KNOWN_GUIDS
import re

logger = logging.getLogger(__name__)

NTUSER_SHELLBAG = "\\Software\\Microsoft\\Windows\\Shell\\BagMRU"
DEFAULT_CODEPAGE = "cp1252"


class ShellBagNtuserPlugin(Plugin):
    NAME = "ntuser_shellbag_plugin"
    DESCRIPTION = "Parse NTUSER Shellbag items"
    COMPATIBLE_HIVE = NTUSER_HIVE_TYPE

    @staticmethod
    def _parse_mru(mru_val):
        mru_order_string = ""
        if isinstance(mru_val, bytes):
            mru_val = mru_val[:-4]
            for i in range(0, len(mru_val), 4):
                current_val = int.from_bytes(mru_val[i : i + 4], byteorder="little")
                mru_order_string += f"{current_val}-"

            return mru_order_string[:-1]
        else:
            return mru_order_string

    @staticmethod
    def _get_shell_item_type(shell_item):
        try:
            import pyfwsi
        except ModuleNotFoundError as ex:
            logger.exception(
                "Plugin `shellbag_plugin` has missing modules, install regipy using"
                " `pip install regipy[full]` in order to install plugin dependencies. "
                "This might take some time... "
            )
            raise ex

        if isinstance(shell_item, pyfwsi.volume):
            item_type = "Volume"

        elif isinstance(shell_item, pyfwsi.file_entry):
            item_type = "Directory"

        elif isinstance(shell_item, pyfwsi.network_location):
            item_type = "Network Location"

        elif isinstance(shell_item, pyfwsi.root_folder):
            item_type = "Root Folder"

        elif isinstance(shell_item, pyfwsi.control_panel_category):
            item_type = "Control Panel Category"

        elif isinstance(shell_item, pyfwsi.control_panel_item):
            item_type = "Control Panel Item"

        elif isinstance(shell_item, pyfwsi.users_property_view):
            item_type = "Users Property View"

        else:
            item_type = "unknown"

        return item_type

    @staticmethod
    def _check_known_guids(guid):
        if guid in KNOWN_GUIDS:
            path_segment = KNOWN_GUIDS[guid]
        else:
            path_segment = "{{{0:s}}}".format(guid)
        return path_segment

    @staticmethod
    def _get_entry_string(fwps_record):
        if fwps_record.entry_name:
            entry_string = fwps_record.entry_name
        else:
            entry_string = f"{fwps_record.entry_type:d}"
        return entry_string

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
            import pyfwps
        except ModuleNotFoundError as ex:
            logger.exception(
                f"Plugin `shellbag_plugin` has missing modules, install regipy using"
                f" `pip install regipy[full]` in order to install plugin dependencies. "
                f"This might take some time... "
            )
            raise ex

        path_segment = None
        full_path = None
        location_description = None

        if isinstance(shell_item, pyfwsi.volume):
            if shell_item.name:
                path_segment = shell_item.name
            elif shell_item.identifier:
                path_segment = self._check_known_guids(shell_item.identifier)

        elif isinstance(shell_item, pyfwsi.file_entry):
            long_name = ""
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
            if shell_item.description:
                location_description = shell_item.description
                if shell_item.comments:
                    location_description += f", {shell_item.comments}"

        elif isinstance(shell_item, pyfwsi.root_folder):
            if shell_item.shell_folder_identifier in KNOWN_GUIDS:
                path_segment = KNOWN_GUIDS[shell_item.shell_folder_identifier]
            elif hasattr(shell_item, "identifier") and shell_item.identifier in KNOWN_GUIDS:
                path_segment = KNOWN_GUIDS[shell_item.identifier]
            else:
                path_segment = "{{{0:s}}}".format(shell_item.shell_folder_identifier)

        elif isinstance(shell_item, pyfwsi.users_property_view):
            # Users property view
            if shell_item.delegate_folder_identifier in KNOWN_GUIDS:
                path_segment = KNOWN_GUIDS[shell_item.delegate_folder_identifier]
            elif hasattr(shell_item, "identifier") and shell_item.identifier in KNOWN_GUIDS:
                path_segment = KNOWN_GUIDS[shell_item.identifier]

            # Variable: Users property view
            elif shell_item.property_store_data:
                fwps_store = pyfwps.store()
                fwps_store.copy_from_byte_stream(shell_item.property_store_data)

                for fwps_set in iter(fwps_store.sets):
                    if fwps_set.identifier == "b725f130-47ef-101a-a5f1-02608c9eebac":
                        for fwps_record in iter(fwps_set.records):
                            entry_string = self._get_entry_string(fwps_record)

                            # PKEY_DisplayName: {b725f130-47ef-101a-a5f1-02608c9eebac}/10
                            if entry_string == "10":
                                if fwps_record.value_type == 0x0001:
                                    value_string = "<VT_NULL>"
                                elif fwps_record.value_type in (
                                    0x0003,
                                    0x0013,
                                    0x0014,
                                    0x0015,
                                ):
                                    value_string = str(fwps_record.get_data_as_integer())
                                elif fwps_record.value_type in (0x0008, 0x001E, 0x001F):
                                    value_string = fwps_record.get_data_as_string()
                                elif fwps_record.value_type == 0x000B:
                                    value_string = str(fwps_record.get_data_as_boolean())
                                elif fwps_record.value_type == 0x0040:
                                    filetime = fwps_record.get_data_as_integer()
                                    value_string = self._FormatFiletimeValue(filetime)
                                elif fwps_record.value_type == 0x0042:
                                    # TODO: add support
                                    value_string = "<VT_STREAM>"
                                elif fwps_record.value_type == 0x0048:
                                    value_string = fwps_record.get_data_as_guid()
                                elif fwps_record.value_type & 0xF000 == 0x1000:
                                    # TODO: add support
                                    value_string = "<VT_VECTOR>"
                                else:
                                    value_string = None

                                path_segment = value_string

                    elif fwps_set.identifier == "28636aa6-953d-11d2-b5d6-00c04fd918d0":
                        for fwps_record in iter(fwps_set.records):
                            entry_string = self._get_entry_string(fwps_record)

                            # PKEY_ParsingPath: {28636aa6-953d-11d2-b5d6-00c04fd918d0}/30
                            if entry_string == "30":
                                full_path = fwps_record.get_data_as_string()

        elif isinstance(shell_item, pyfwsi.control_panel_category):
            path_segment = self._check_known_guids(str(shell_item.identifier))

        elif isinstance(shell_item, pyfwsi.control_panel_item):
            path_segment = self._check_known_guids(shell_item.identifier)

        if path_segment is None:
            path_segment = "<UNKNOWN: 0x{0:02x}>".format(shell_item.class_type)

        return path_segment, full_path, location_description

    def iter_sk(self, key, reg_path, codepage=DEFAULT_CODEPAGE, base_path="", path=""):
        try:
            import pyfwsi
        except ModuleNotFoundError as ex:
            logger.exception(
                f"Plugin `shellbag_plugin` has missing modules, install regipy using"
                f" `pip install regipy[full]` in order to install plugin dependencies. "
                f"This might take some time... "
            )
            raise ex

        last_write = convert_wintime(key.header.last_modified, as_json=True)

        mru_val = key.get_value("MRUListEx")
        mru_order = self._parse_mru(mru_val)
        base_path = path

        if key.get_value("NodeSlot"):
            node_slot = str(key.get_value("NodeSlot"))
        else:
            node_slot = ""

        for v in key.iter_values(trim_values=False):
            if re.match(r"\d+", v.name):
                slot = v.name
                byte_stream = v.value
                shell_items = pyfwsi.item_list()
                shell_items.copy_from_byte_stream(byte_stream, ascii_codepage=codepage)
                for item in shell_items.items:
                    shell_type = self._get_shell_item_type(item)
                    value, full_path, location_description = self._parse_shell_item_path_segment(self, item)
                    if not path:
                        path = value
                        base_path = ""
                    else:
                        path += f"\\{value}"

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
                                    logger.exception(f"Malformed creation time for {path}")
                                try:
                                    access_time = extension_block.get_access_time()
                                    if self.as_json:
                                        access_time = access_time.isoformat()
                                except OSError:
                                    logger.exception(f"Malformed access time for {path}")

                    try:
                        if hasattr(item, "modification_time"):
                            modification_time = item.get_modification_time()
                            if self.as_json:
                                modification_time = modification_time.isoformat()
                    except OSError:
                        logger.exception(f"Malformed modification time for {path}")

                    value_name = v.name
                    mru_order_location = mru_order.split("-").index(value_name)
                    entry = {
                        "value": value,
                        "slot": slot,
                        "reg_path": reg_path,
                        "value_name": value_name,
                        "node_slot": node_slot,
                        "shell_type": shell_type,
                        "path": path,
                        "full path": full_path if full_path else None,
                        "location description": (location_description if location_description else None),
                        "creation_time": creation_time,
                        "access_time": access_time,
                        "modification_time": modification_time,
                        "last_write": last_write,
                        "mru_order": mru_order,
                        "mru_order_location": mru_order_location,
                    }

                    self.entries.append(entry)
                    sk_reg_path = f"{reg_path}\\{value_name}"
                    sk = self.registry_hive.get_key(sk_reg_path)
                    self.iter_sk(sk, sk_reg_path, codepage, base_path, path)
                    path = base_path

    def run(self, codepage=DEFAULT_CODEPAGE):
        try:
            # flake8: noqa
            import pyfwsi
        except ModuleNotFoundError as ex:
            logger.exception(
                "Plugin `shellbag_plugin` has missing modules, install regipy using"
                " `pip install regipy[full]` in order to install plugin dependencies. "
                "This might take some time... "
            )
            raise ex

        try:
            shellbag_ntuser_subkey = self.registry_hive.get_key(NTUSER_SHELLBAG)
            self.iter_sk(shellbag_ntuser_subkey, NTUSER_SHELLBAG, codepage=codepage)
        except RegistryKeyNotFoundException as ex:
            logger.error(f"Could not find {self.NAME} plugin data at: {NTUSER_SHELLBAG}: {ex}")
