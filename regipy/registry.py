import binascii
import datetime as dt

from typing import List, Optional, Union

import logging

import attr

from construct import Bytes, CString, EnumIntegerString, GreedyRange, Int32sl, Int32ul, Int64ul, \
    StreamError, ConstError
from io import BytesIO

from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException, NoRegistryValuesException, \
    RegistryValueNotFoundException, RegipyGeneralException, UnidentifiedHiveException, RegistryParsingException
from regipy.hive_types import SUPPORTED_HIVE_TYPES
from regipy.security_utils import convert_sid, get_acls
from regipy.structs import REGF_HEADER, HBIN_HEADER, CM_KEY_NODE, LF_LH_SK_ELEMENT, VALUE_KEY, INDEX_ROOT, \
    REGF_HEADER_SIZE, INDEX_ROOT_SIGNATURE, LEAF_INDEX_SIGNATURE, FAST_LEAF_SIGNATURE, HASH_LEAF_SIGNATURE, \
    BIG_DATA_BLOCK, INDEX_LEAF, DEFAULT_VALUE, SECURITY_KEY_v1_1, SECURITY_DESCRIPTOR, SID, ACL, ACE, VALUE_TYPE_ENUM
from regipy.utils import boomerang_stream, convert_wintime, identify_hive_type, MAX_LEN, try_decode_binary

logger = logging.getLogger(__name__)


@attr.s
class Cell:
    """
    Represents a Registry cell header
    """
    offset: int = attr.ib()
    cell_type: str = attr.ib()
    size: int = attr.ib()


@attr.s
class VKRecord:
    """
    The VK Record contains a value
    """
    value_type: EnumIntegerString = attr.ib()
    value_type_str: str = attr.ib()
    value: bytes = attr.ib()
    size: int = attr.ib(default=0)
    is_corrupted: bool = attr.ib(default=False)


@attr.s
class LIRecord:
    data: bytes = attr.ib()


@attr.s
class Value:
    name: str = attr.ib()
    value: Union[str, int, bytes] = attr.ib()
    value_type: str = attr.ib()
    is_corrupted: bool = attr.ib(default=False)


@attr.s
class Subkey:
    subkey_name: str = attr.ib()
    path: str = attr.ib()
    timestamp: dt.datetime = attr.ib()
    values_count: int = attr.ib()
    values: List[Value] = attr.ib(factory=list)

    # This field will be used if a partial hive was given, if not it would be None.
    actual_path: Optional[str] = attr.ib(default=None)


class RIRecord:
    data = None
    header = None

    def __init__(self, stream):
        self.header = INDEX_ROOT.parse_stream(stream)


class RegistryHive:
    CONTROL_SETS = [r'\ControlSet001', r'\ControlSet002']

    def __init__(self, hive: Union[str, bytes], hive_type=None, partial_hive_path=None):
        """
        Represents a registry hive
        :param hive: Path to the registry hive or raw data of the registry hive
        :param hive_type: The hive type can be specified if this is a partial hive,
                          or for some other reason regipy cannot identify the hive type
        :param partial_hive_path: The path from which the partial hive actually starts, for example:
                                  hive_type=ntuser partial_hive_path="/Software" would mean
                                  this is actually a HKCU hive, starting from HKCU/Software
        """

        self.partial_hive_path = None
        self.hive_type = None

        if type(hive) == str:
            with open(hive, 'rb') as f:
                self._stream = BytesIO(f.read())
        if type(hive) == bytes:
            self._stream = BytesIO(hive)

        with boomerang_stream(self._stream) as s:
            self.header = REGF_HEADER.parse_stream(s)

            # Get the first cell in root HBin, which is the root NKRecord:
            root_hbin = self.get_hbin_at_offset()
            root_hbin_cell = next(root_hbin.iter_cells(s))
            self.root = NKRecord(root_hbin_cell, s)
        self.name = self.header.file_name

        if hive_type:
            if hive_type.lower() in SUPPORTED_HIVE_TYPES:
                self.hive_type = hive_type
            else:
                raise UnidentifiedHiveException(f'{hive_type} is not a supported hive type: '
                                                f'only the following are supported: {SUPPORTED_HIVE_TYPES}')
        else:
            try:
                self.hive_type = identify_hive_type(self.name)
            except UnidentifiedHiveException:
                if type(hive) == str:
                    logger.info(f'Hive type for {hive} was not identified: {self.name}')
                if type(hive) == bytes:
                    logger.info(f'Hive type was not identified: {self.name}')

        if partial_hive_path:
            self.partial_hive_path = partial_hive_path

    def recurse_subkeys(self, nk_record=None, path_root=None, as_json=False, is_init=True, fetch_values=True):
        """
        Recurse over a subkey, and yield all of its subkeys and values
        :param nk_record: an instance of NKRecord from which to start iterating, if None, will start from Root
        :param path_root: If we are iterating an incomplete hive, for example a hive tree starting
                          from ControlSet001 and not SYSTEM, there is no way to know that.
                          This string will be added as prefix to all paths.
        :param as_json: Whether to normalize the data as JSON or not
        :param fetch_values: If False, subkey values will not be returned, but the iteration will be faster
        """
        # If None, will start iterating from Root NK entry
        if not nk_record:
            nk_record = self.root

        # Iterate over subkeys
        if nk_record.header.subkey_count:
            for subkey in nk_record.iter_subkeys():
                if path_root:
                    subkey_path = r'{}\{}'.format(path_root, subkey.name) if path_root else r'\{}'.format(subkey.name)
                else:
                    subkey_path = f'\\{subkey.name}'

                # Leaf Index records do not contain subkeys
                if isinstance(subkey, LIRecord):
                    continue

                if subkey.subkey_count:
                    yield from self.recurse_subkeys(nk_record=subkey,
                                                    path_root=subkey_path,
                                                    as_json=as_json,
                                                    is_init=False,
                                                    fetch_values=fetch_values)

                values = []
                if fetch_values:
                    if subkey.values_count:
                        try:
                            if as_json:
                                values = [attr.asdict(x) for x in subkey.iter_values(as_json=as_json)]
                            else:
                                values = list(subkey.iter_values(as_json=as_json))
                        except RegistryParsingException as ex:
                            logger.exception(f'Failed to parse hive value at path: {path_root}')

                ts = convert_wintime(subkey.header.last_modified)
                yield Subkey(subkey_name=subkey.name, path=subkey_path,
                             timestamp=ts.isoformat() if as_json else ts, values=values,
                             values_count=subkey.values_count,
                             actual_path=f'{self.partial_hive_path}{subkey_path}' if self.partial_hive_path else None)

        if is_init:
            # Get the values of the subkey
            values = []
            if nk_record.values_count:
                try:
                    if as_json:
                        values = [attr.asdict(x) for x in nk_record.iter_values(as_json=as_json)]
                    else:
                        values = list(nk_record.iter_values(as_json=as_json))
                except RegistryParsingException as ex:
                    logger.exception(f'Failed to parse hive value at path: {path_root}')
                    values = []

            ts = convert_wintime(nk_record.header.last_modified)
            subkey_path = path_root or '\\'
            yield Subkey(subkey_name=nk_record.name, path=subkey_path,
                         timestamp=ts.isoformat() if as_json else ts, values=values, values_count=len(values),
                         actual_path=f'{self.partial_hive_path}\\{subkey_path}' if self.partial_hive_path else None)

    def get_hbin_at_offset(self, offset=0):
        """
        This offset is from start of data (meaning that it starts from 4096)
        If not offset is given, will return the root Hbin
        :return:
        """
        self._stream.seek(REGF_HEADER_SIZE + offset)
        return HBin(self._stream)

    def get_key(self, key_path):
        if self.partial_hive_path:
            if key_path.startswith(self.partial_hive_path):
                key_path = key_path.partition(self.partial_hive_path)[-1]
            else:
                raise RegistryKeyNotFoundException(f'Did not find subkey at {key_path}, because this is a partial hive')

        logger.debug('Getting key: {}'.format(key_path))

        # If the key path is \ we are just refering to root
        if key_path == '\\':
            return self.root

        # If the path contain slashes, this is a full path. Split it
        if '\\' in key_path:
            key_path_parts = key_path.split('\\')[1:]
        else:
            key_path_parts = [key_path]

        previous_key_name = []

        subkey = self.root.get_subkey(key_path_parts.pop(0), raise_on_missing=False)

        if not subkey:
            raise RegistryKeyNotFoundException('Did not find subkey at {}'.format(key_path))

        if not key_path_parts:
            return subkey

        for path_part in key_path_parts:
            new_path = '\\'.join(previous_key_name)
            previous_key_name.append(subkey.name)
            subkey = subkey.get_subkey(path_part, raise_on_missing=False)

            if not subkey:
                raise RegistryKeyNotFoundException('Did not find {} at {}'.format(path_part, new_path))
        return subkey

    def get_control_sets(self, registry_path):
        """
        Get the optional control sets for a registry hive
        :param registry_path:
        :return: A list of paths, including the control sets
        """

        found_control_sets = []
        for cs in self.CONTROL_SETS:
            try:
                found_control_sets.append(self.get_key(cs))
            except RegistryKeyNotFoundException:
                continue
        result = [r'\{}\{}'.format(subkey.name, registry_path) for subkey in found_control_sets]
        logger.debug('Found control sets: {}'.format(result))
        return result


class HBin:
    def __init__(self, stream):
        """
        :param stream: a stream at the start of the hbin block
        """
        self.header = HBIN_HEADER.parse_stream(stream)
        self.hbin_data_offset = stream.tell()

    def iter_cells(self, stream):
        stream.seek(self.hbin_data_offset)
        offset = stream.tell()
        while offset < self.hbin_data_offset + self.header.size - HBIN_HEADER.sizeof():
            hbin_cell_size = Int32sl.parse_stream(stream)

            # If the cell size is positive, it means it is unallocated. We are not interested in those on a regular run
            if hbin_cell_size >= 0:
                continue

            bytes_to_read = (hbin_cell_size * -1) - 4

            cell_type = Bytes(2).parse_stream(stream)

            # Yield the cell
            yield Cell(cell_type=cell_type.decode(), offset=stream.tell(), size=bytes_to_read)

            # Go to the next cell
            offset += stream.tell() + bytes_to_read


class NKRecord:
    """
    The NKRecord represents a Name Key entry
    """

    def __init__(self, cell, stream):
        stream.seek(cell.offset)
        self.header = CM_KEY_NODE.parse_stream(stream)
        self._stream = stream

        # Sometimes the key names are ASCII and sometimes UTF-16 little endian
        if self.header.flags.KEY_COMP_NAME:
            # Compressed (ASCII) key name
            self.name = self.header.key_name_string.decode('ascii', errors='replace')
        else:
            # Unicode (UTF-16) key name
            self.name = self.header.key_name_string.decode('utf-16-le', errors='replace')
            logger.debug(f'Unicode key name identified: "{self.name}"')

        self.subkey_count = self.header.subkey_count
        self.values_count = self.header.values_count
        self.volatile_subkeys_count = self.header.volatile_subkey_count

    def get_subkey(self, key_name, raise_on_missing=True):
        if not self.subkey_count and raise_on_missing:
            raise NoRegistrySubkeysException('No subkeys for {}'.format(self.header.key_name_string))

        for subkey in self.iter_subkeys():
            # This should not happen
            if not isinstance(subkey, NKRecord):
                raise RegipyGeneralException(f'Unknown record type: {subkey}')

            if subkey.name.upper() == key_name.upper():
                return subkey

        if raise_on_missing:
            raise NoRegistrySubkeysException('No subkey {} for {}'.format(key_name, self.header.key_name_string))

    def iter_subkeys(self):

        if not self.header.subkey_count:
            return None

        # Go to the offset where the subkey list starts (+4 is because of the cell header)
        target_offset = REGF_HEADER_SIZE + 4 + self.header.subkeys_list_offset
        self._stream.seek(target_offset)

        # Read the signature
        try:
            signature = Bytes(2).parse_stream(self._stream)
        except StreamError as ex:
            raise RegistryParsingException(f'Bad subkey at offset {target_offset}: {ex}')

        # LF,  LH and RI contain subkeys
        if signature in [HASH_LEAF_SIGNATURE, FAST_LEAF_SIGNATURE, LEAF_INDEX_SIGNATURE]:
            yield from self._parse_subkeys(self._stream, signature=signature)
        # RI contains pointers to arrays of subkeys
        elif signature == INDEX_ROOT_SIGNATURE:
            ri_record = RIRecord(self._stream)
            if ri_record.header.element_count > 0:
                for element in ri_record.header.elements:
                    # We skip 6 because of the signature as well as the cell header
                    element_target_offset = REGF_HEADER_SIZE + 4 + element.subkey_list_offset
                    self._stream.seek(element_target_offset)
                    yield from self._parse_subkeys(self._stream)

    @staticmethod
    def _parse_subkeys(stream, signature=None):
        """
        Parse an LI , LF or LH Record
        :param stream: A stream at the header of the LH or LF entry, skipping the signature
        :return:
        """
        if not signature:
            signature = stream.read(2)

        if signature in [HASH_LEAF_SIGNATURE, FAST_LEAF_SIGNATURE]:
            subkeys = LF_LH_SK_ELEMENT.parse_stream(stream)
        elif signature == LEAF_INDEX_SIGNATURE:
            subkeys = INDEX_LEAF.parse_stream(stream)
        else:
            raise RegistryParsingException(f'Expected a known signature, got: {signature} at offset {stream.tell()}')

        for subkey in subkeys.elements:
            stream.seek(REGF_HEADER_SIZE + subkey.key_node_offset)

            # This cell should always be allocated, therefor we expect a negative size
            cell_size = Int32sl.parse_stream(stream) * -1

            # We read to this offset and skip 2 bytes, because that is the cell size we just read
            nk_cell = Cell(cell_type='nk', offset=stream.tell() + 2, size=cell_size)
            nk_record = NKRecord(cell=nk_cell, stream=stream)
            yield nk_record

    @staticmethod
    def read_value(vk, stream):
        """
        Read a registry value
        :param vk: A parse VK record
        :param stream: The registry stream
        :return: A VKRecord
        """
        stream.seek(REGF_HEADER_SIZE + 4 + vk.data_offset)
        data_type = vk.data_type
        data = stream.read(vk.data_size)
        return VKRecord(value_type=data_type, value_type_str=str(data_type), value=data, size=vk.data_size)

    @staticmethod
    def _parse_indirect_block(stream, value):
        # This is an indirect datablock (Bigger than 16344, therefor we handle it differently)
        # The value inside the vk entry actually contains a pointer to the buffers containing the data
        big_data_block_header = BIG_DATA_BLOCK.parse(value.value)

        # Go to the start of the segment offset list
        stream.seek(REGF_HEADER_SIZE + big_data_block_header.offset_to_list_of_segments)
        buffer = BytesIO()

        # Read them sequentially until we got all the size of the VK
        value_size = value.size
        while value_size > 0:
            data_segment_offset = Int32ul.parse_stream(stream)
            with boomerang_stream(stream) as tmpstream:
                tmpstream.seek(REGF_HEADER_SIZE + 4 + data_segment_offset)
                tmpbuffer = tmpstream.read(min(0x3fd8, value_size))
                value_size -= len(tmpbuffer)
                buffer.write(tmpbuffer)
        buffer.seek(0)
        return buffer.read()

    def iter_values(self, as_json=False, max_len=MAX_LEN, trim_values=True):
        """
        Get the values of a subkey. Will raise if no values exist
        :param as_json: Whether to normalize the data as JSON or not
        :param max_len: Max length of value to return
        :param trim_values: whether to trim values to MAX_LEN
        :return: List of values for the subkey
        """
        if not self.values_count:
            return

        # Get the offset of the values key. We skip 4 because of Cell Header
        target_offset = REGF_HEADER_SIZE + 4 + self.header.values_list_offset
        self._stream.seek(target_offset)

        for _ in range(self.values_count):
            is_corrupted = False
            try:
                vk_offset = Int32ul.parse_stream(self._stream)
            except StreamError:
                logger.info(f'Skipping bad registry VK at {self._stream.tell()}')
                raise RegistryParsingException(f'Bad registry VK at {self._stream.tell()}')

            with boomerang_stream(self._stream) as substream:
                actual_vk_offset = REGF_HEADER_SIZE + 4 + vk_offset
                substream.seek(actual_vk_offset)
                try:
                    vk = VALUE_KEY.parse_stream(substream)
                except (ConstError, StreamError):
                    logger.error(f'Could not parse VK at {substream.tell()}, registry hive is probably corrupted.')
                    return

                value = self.read_value(vk, substream)

                if vk.name_size == 0:
                    value_name = '(default)'
                elif vk.flags.VALUE_COMP_NAME:
                    # Compressed (ASCII) value name
                    value_name = vk.name.decode('ascii', errors='replace')
                else:
                    # Unicode (UTF-16) value name
                    value_name = vk.name.decode('utf-16-le', errors='replace')
                    logger.debug(f'Unicode value name identified: "{value_name}"')

                # If the value is bigger than this value, it means this is a DEVPROP structure
                # https://doxygen.reactos.org/d0/dba/devpropdef_8h_source.html
                # https://sourceforge.net/p/mingw-w64/mingw-w64/ci/668a1d3e85042c409e0c292e621b3dc0aa26177c/tree/
                # mingw-w64-headers/include/devpropdef.h?diff=dd86a3b7594dadeef9d6a37c4b6be3ca42ef7e94
                # We currently do not support these, We are going to make the best effort to dump as string.
                # This int casting will always work because the data_type is construct's EnumIntegerString
                if int(vk.data_type) > 0xffff0000:
                    data_type = VALUE_TYPE_ENUM.parse(Int32ul.build(int(vk.data_type) & 0xffff))
                    logger.info(f"Value at {hex(actual_vk_offset)} contains DEVPROP structure of type {data_type}")

                # Skip this unknown data type, research pending :)
                # TODO: Add actual parsing
                elif int(vk.data_type) == 0x200000:
                    logger.info(f"Skipped unknown data type value at {actual_vk_offset}")
                    continue
                else:
                    data_type = str(vk.data_type)

                if data_type in ['REG_SZ', 'REG_EXPAND', 'REG_EXPAND_SZ']:
                    if vk.data_size >= 0x80000000:
                        # data is contained in the data_offset field
                        value.size -= 0x80000000
                        actual_value = vk.data_offset
                    elif vk.data_size > 0x3fd8 and value.value[:2] == b'db':
                        data = self._parse_indirect_block(substream, value)
                        actual_value = try_decode_binary(data, as_json=as_json, trim_values=trim_values)
                    else:
                        actual_value = try_decode_binary(value.value, as_json=as_json, trim_values=trim_values)
                elif data_type in ['REG_BINARY', 'REG_NONE']:
                    if vk.data_size >= 0x80000000:
                        # data is contained in the data_offset field
                        actual_value = vk.data_offset
                    elif vk.data_size > 0x3fd8 and value.value[:2] == b'db':
                        try:
                            actual_value = self._parse_indirect_block(substream, value)

                            actual_value = try_decode_binary(actual_value, as_json=True, trim_values=trim_values) if as_json else actual_value
                        except ConstError:
                            logger.error(f'Bad value at {actual_vk_offset}')
                            continue
                    else:
                        # Return the actual data
                        actual_value = binascii.b2a_hex(value.value).decode()[:max_len] if trim_values else value.value
                elif data_type == 'REG_SZ':
                    actual_value = try_decode_binary(value.value, as_json=as_json, trim_values=trim_values)
                elif data_type == 'REG_DWORD':
                    # If the data size is bigger than 0x80000000, data is actually stored in the VK data offset.
                    actual_value = vk.data_offset if vk.data_size >= 0x80000000 else Int32ul.parse(value.value)
                elif data_type == 'REG_QWORD':
                    actual_value = vk.data_offset if vk.data_size >= 0x80000000 else Int64ul.parse(value.value)
                elif data_type == 'REG_MULTI_SZ':
                    parsed_value = GreedyRange(CString('utf-16-le')).parse(value.value)
                    # Because the ListContainer object returned by Construct cannot be turned into a list,
                    # we do this trick
                    actual_value = [x for x in parsed_value if x]
                # We currently dumps this as hex string or raw
                # TODO: Add actual parsing
                elif data_type in ['REG_RESOURCE_REQUIREMENTS_LIST', 'REG_RESOURCE_LIST']:
                    actual_value = binascii.b2a_hex(value.value).decode()[:max_len] if trim_values else value.value
                elif data_type == 'REG_FILETIME':
                    actual_value = convert_wintime(Int64ul.parse(value.value), as_json=as_json)
                else:
                    actual_value = try_decode_binary(value.value, as_json=as_json, trim_values=trim_values)
                yield Value(name=value_name, value_type=data_type, value=actual_value,
                            is_corrupted=is_corrupted)

    def get_value(self, value_name=DEFAULT_VALUE, as_json=False, raise_on_missing=False, case_sensitive=True):
        """
        Get a value by name. Will raise if raise_on_missing is set,
        if no value name is given, will return the content of the default value
        :param value_name: The value name to look for
        :param as_json: Whether to normalize the data as JSON or not
        :param raise_on_missing: Will raise exception if value is missing, else will return None
        :return:
        """
        value_name = value_name if case_sensitive else value_name.lower()
        for value in self.iter_values(as_json=as_json, trim_values=False):
            v = value.name if case_sensitive else value.name.lower()
            if v == value_name:
                return value.value

        if raise_on_missing:
            raise RegistryValueNotFoundException('Did not find the value {} on subkey {}'.format(value_name, self.name))
        return None

    def get_values(self, as_json=False, trim_values=False):
        return [x for x in self.iter_values(as_json=as_json, trim_values=trim_values)]

    def get_security_key_info(self):
        self._stream.seek(REGF_HEADER_SIZE + self.header.security_key_offset)
        # TODO: If parsing fails, parse with SECURITY_KEY_v1_2
        security_key = SECURITY_KEY_v1_1.parse_stream(self._stream)
        security_descriptor = SECURITY_DESCRIPTOR.parse(security_key.security_descriptor)

        with boomerang_stream(self._stream) as s:
            security_base_offset = REGF_HEADER_SIZE + self.header.security_key_offset + 24

            s.seek(security_base_offset + security_descriptor.owner)
            owner_sid = convert_sid(SID.parse_stream(s))

            s.seek(security_base_offset + security_descriptor.group)
            group_sid = convert_sid(SID.parse_stream(s))

            sacl_aces = None
            if security_descriptor.offset_sacl > 0:
                s.seek(security_base_offset + security_descriptor.offset_sacl)
                sacl_aces = get_acls(s)

            dacl_aces = None
            if security_descriptor.offset_dacl > 0:
                s.seek(security_base_offset + security_descriptor.offset_dacl)
                dacl_aces = get_acls(s)
            return {
                'owner': owner_sid,
                'group': group_sid,
                'dacl': dacl_aces,
                'sacl': sacl_aces
            }

    def get_class_name(self) -> str:
        """
        Gets the key class name as would be returned via
        the `lpClass` argument of the `RegQueryInfoKey()` function.
        """

        # Get the offset of the class name string. We skip 4 because of Cell Header
        read_offset = REGF_HEADER_SIZE + 4 + self.header.class_name_offset

        self._stream.seek(read_offset)
        class_name = self._stream.read(self.header.class_name_size)

        return class_name.decode('utf-16-le', errors='replace')

    def __dict__(self):
        return {
            'name': self.name,
            'subkey_count': self.subkey_count,
            'value_count': self.values_count,
            'values': {x['name']: x['value'] for x in self.iter_values()} if self.values_count else None,
            'subkeys': {x['name'] for x in self.iter_subkeys()} if self.subkey_count else None,
            'timestamp': convert_wintime(self.header.last_modified, as_json=True),
            'volatile_subkeys': self.volatile_subkeys_count
        }
