import binascii
import datetime as dt

import jsonlines
import logbook

import attr

from construct import *
from io import BytesIO

from tqdm import tqdm

from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException, NoRegistryValuesException, \
    RegistryValueNotFoundException, RegipyGeneralException, UnidentifiedHiveException
from regipy.structs import REGF_HEADER, HBIN_HEADER, CM_KEY_NODE, LF_LH_SK_ELEMENT, VALUE_KEY, INDEX_ROOT, \
    REGF_HEADER_SIZE, INDEX_ROOT_SIGNATURE, LEAF_INDEX_SIGNATURE, FAST_LEAF_SIGNATURE, HASH_LEAF_SIGNATURE, \
    BIG_DATA_BLOCK
from regipy.utils import boomerang_stream, convert_wintime, identify_hive_type, MAX_LEN, try_decode_binary

logger = logbook.Logger(__name__)


@attr.s
class Cell:
    """
    Represents a Registry cell header
    """
    offset = attr.ib(type=int)
    cell_type = attr.ib(type=str)
    size = attr.ib(type=int)


@attr.s
class VKRecord:
    """
    The VK Record contains a value
    """
    value_type = attr.ib(type=EnumIntegerString)
    value_type_str = attr.ib(type=str)
    value = attr.ib(type=bytes)
    size = attr.ib(type=int, default=0)
    is_corrupted = attr.ib(type=bool, default=False)


@attr.s
class LIRecord:
    data = attr.ib(type=bytes)


@attr.s
class Subkey:
    subkey_name = attr.ib(type=str)
    path = attr.ib(type=str)
    timestamp = attr.ib(type=dt.datetime)
    values_count = attr.ib(type=int)
    values = attr.ib(factory=list)


@attr.s
class Value:
    name = attr.ib(type=str)
    value = attr.ib(type=(str or bytes))
    value_type = attr.ib(type=str)
    is_corrupted = attr.ib(type=bool, default=False)


class RIRecord:
    data = None
    header = None

    def __init__(self, stream):
        self.header = INDEX_ROOT.parse_stream(stream)


class RegistryHive:
    CONTROL_SETS = [r'\ControlSet001', r'\ControlSet002']

    def __init__(self, hive_path):
        """
        Represents a registry hive
        :param hive_path: Path to the registry hive
        """
        with open(hive_path, 'rb') as f:
            self._stream = BytesIO(f.read())

        with boomerang_stream(self._stream) as s:
            self.header = REGF_HEADER.parse_stream(s)

            # Get the first cell in root HBin, which is the root NKRecord:
            root_hbin = self.get_hbin_at_offset()
            root_hbin_cell = next(root_hbin.iter_cells(s))
            self.root = NKRecord(root_hbin_cell, s)
        self.name = self.header.file_name

        try:
            self.hive_type = identify_hive_type(self.name)
        except UnidentifiedHiveException:
            self.hive_type = None

    def recurse_subkeys(self, nk_record=None, path=None, as_json=False):
        """
        Recurse over a subkey, and yield all of its subkeys and values
        :param nk_record: an instance of NKRecord from which to start iterating, if None, will start from Root
        :param path: The current registry path
        :param as_json: Whether to normalize the data as JSON or not
        """
        # If None, will start iterating from Root NK entry
        if not nk_record:
            nk_record = self.root

        # Iterate over subkeys
        for subkey in nk_record.iter_subkeys():
            if subkey.subkey_count:
                if path:
                    yield from self.recurse_subkeys(nk_record=subkey, path=r'{}\{}'.format(path, subkey.name),
                                                    as_json=as_json)
                else:
                    yield from self.recurse_subkeys(nk_record=subkey, path=r'\{}'.format(subkey.name), as_json=as_json)

            values = []
            if subkey.values_count:
                if as_json:
                    values = [attr.asdict(x) for x in subkey.iter_values(as_json=as_json)]
                else:
                    values = list(subkey.iter_values(as_json=as_json))

            ts = convert_wintime(subkey.header.last_modified)
            yield Subkey(subkey_name=subkey.name, path=r'{}\{}'.format(path, subkey.name) if path else '\\',
                         timestamp=ts.isoformat() if as_json else ts, values=values,
                         values_count=len(values))

        # Get the values of the subkey
        values = []
        if nk_record.values_count:
            if as_json:
                values = [attr.asdict(x) for x in nk_record.iter_values(as_json=as_json)]
            else:
                values = list(nk_record.iter_values(as_json=as_json))

        ts = convert_wintime(nk_record.header.last_modified)
        yield Subkey(subkey_name=nk_record.name, path=path,
                     timestamp=ts.isoformat() if as_json else ts, values=values, values_count=len(values))

    def get_hbin_at_offset(self, offset=0):
        """
        This offset is from start of data (meaning that it starts from 4096)
        If not offset is given, will return the root Hbin
        :return:
        """
        self._stream.seek(REGF_HEADER_SIZE + offset)
        return HBin(self._stream)

    def get_key(self, key_path):
        logger.debug('Getting key: {}'.format(key_path))

        if key_path == '\\':
            return self.root

        key_path_parts = key_path.split('\\')[1:]
        previous_key_name = ['root']
        subkey = self.root.get_key(key_path_parts.pop(0))

        if not subkey:
            raise RegistryKeyNotFoundException(
                'Did not find {} at {}'.format(key_path, r'\\'.join(previous_key_name)))

        if not key_path_parts:
            return subkey

        for path_part in key_path_parts:
            new_path = '\\'.join(previous_key_name)
            previous_key_name.append(subkey.name)
            subkey = subkey.get_key(path_part)

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
        logger.info('Found control sets: {}'.format(result))
        return result

    def dump_hive_to_json(self, output_path, name_key_entry, verbose=False):
        with jsonlines.open(output_path, mode='w') as writer:
            for entry in tqdm(self.recurse_subkeys(name_key_entry, as_json=True), disable=not verbose):
                writer.write(attr.asdict(entry))


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

        # Sometime the values are utf-8 and sometimes utf-16 little endian, we attempt both
        try:
            decoded_name = self.header.key_name_string.decode()
        except UnicodeDecodeError:
            decoded_name = self.header.key_name_string.decode('utf-16-le', errors='replace')
        self.name = decoded_name

        self.subkey_count = self.header.subkey_count
        self.values_count = self.header.values_count
        self.volatile_subkeys_count = self.header.volatile_subkey_count

    def get_key(self, key_name):
        if not self.subkey_count:
            raise NoRegistrySubkeysException('No subkeys for {}'.format(self.header.key_name_string))

        for subkey in self.iter_subkeys():
            # This should not happen
            if not isinstance(subkey, NKRecord):
                raise RegipyGeneralException(f'Unknown record type: {subkey}')

            if subkey.name == key_name:
                return subkey

    def iter_subkeys(self):

        if not self.header.subkey_count:
            raise NoRegistrySubkeysException('No subkeys for {}'.format(self.name))

        # Go to the offset where the subkey list starts (+4 is because of the cell header)
        target_offset = REGF_HEADER_SIZE + 4 + self.header.subkeys_list_offset
        self._stream.seek(target_offset)

        # Read the signature
        signature = Bytes(2).parse_stream(self._stream)

        # LF and LH contain subkeys
        if signature in [HASH_LEAF_SIGNATURE, FAST_LEAF_SIGNATURE]:
            yield from self._parse_subkeys(self._stream)
        elif signature == LEAF_INDEX_SIGNATURE:
            yield LIRecord(Int32ul.parse_stream(self._stream))
        # RI contains pointers to arrays of subkeys
        elif signature == INDEX_ROOT_SIGNATURE:
            ri_record = RIRecord(self._stream)
            if ri_record.header.element_count > 0:
                for element in ri_record.header.elements:
                    # We skip 6 because of the signature as well as the cell header
                    self._stream.seek(REGF_HEADER_SIZE + 6 + element.subkey_list_offset)
                    yield from self._parse_subkeys(self._stream)

    @staticmethod
    def _parse_subkeys(stream):
        """
        Parse an LF or LH Record
        :param stream: A stream at the header of the LH or LF entry, skipping the signature
        :return:
        """
        subkeys = LF_LH_SK_ELEMENT.parse_stream(stream)
        for subkey in subkeys.elements:
            stream.seek(REGF_HEADER_SIZE + subkey.named_key_offset)

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

    def iter_values(self, as_json=False, max_len=MAX_LEN):
        """
        Get the values of a subkey. Will raise if no values exist
        :param as_json: Whether to normalize the data as JSON or not
        :param max_len: Max length of value to return
        :return: List of values for the subkey
        """
        if not self.values_count:
            raise NoRegistryValuesException(f'No registry values for {self.name}')

        # Get the offset of the values key. We skip 4 because of Cell Header
        target_offset = REGF_HEADER_SIZE + 4 + self.header.values_list_offset
        self._stream.seek(target_offset)

        for _ in range(self.values_count):
            is_corrupted = False
            vk_offset = Int32ul.parse_stream(self._stream)
            with boomerang_stream(self._stream) as substream:
                actual_vk_offset = REGF_HEADER_SIZE + 4 + vk_offset
                substream.seek(actual_vk_offset)
                vk = VALUE_KEY.parse_stream(substream)
                value = self.read_value(vk, substream)

                if vk.name_size == 0:
                    value_name = '(default)'
                else:
                    value_name = vk.name.decode(errors='replace')

                data_type = str(vk.data_type)
                if data_type in ['REG_SZ', 'REG_EXPAND', 'REG_EXPAND_SZ']:
                    if vk.data_size >= 0x80000000:
                        # data is contained in the data_offset field
                        value.size -= 0x80000000
                        actual_value = vk.data_offset
                    elif vk.data_size > 0x3fd8:
                        data = self._parse_indirect_block(substream, value)
                        actual_value = try_decode_binary(data, as_json=as_json)
                    else:
                        actual_value = try_decode_binary(value.value, as_json=as_json)
                elif data_type in ['REG_BINARY', 'REG_NONE']:
                    if vk.data_size >= 0x80000000:
                        # data is contained in the data_offset field
                        actual_value = vk.data_offset
                    elif vk.data_size > 0x3fd8:
                        try:
                            actual_value = self._parse_indirect_block(substream, value)
                            actual_value = try_decode_binary(actual_value, as_json=True) if as_json else actual_value
                        except ConstError:
                            logger.error(f'Bad value at {actual_vk_offset}')
                            continue
                    else:
                        # Return the actual data
                        actual_value = binascii.b2a_hex(value.value).decode()[:max_len] if as_json else value.value
                elif data_type == 'REG_SZ':
                    actual_value = try_decode_binary(value.value, as_json=as_json)
                elif data_type == 'REG_DWORD':
                    # If the data size is bigger than 0x80000000, data is actually stored in the VK data offset.
                    actual_value = vk.data_offset if vk.data_size >= 0x80000000 else Int32ul.parse(value.value)
                elif data_type == 'REG_QWORD':
                    actual_value = vk.data_offset if vk.data_size >= 0x80000000 else Int64ul.parse(value.value)
                elif data_type == 'REG_MULTI_SZ':
                    parsed_value = GreedyRange(CString('utf-16-le')).parse(value.value)
                    # Because the ListContainer object returned by Construct cannot be turned into a list,
                    # we do this trick
                    actual_value = str(parsed_value) if as_json else [x for x in parsed_value if x]
                else:
                    actual_value = try_decode_binary(value.value, as_json=as_json)
                yield Value(name=value_name, value_type=str(value.value_type), value=actual_value,
                            is_corrupted=is_corrupted)

    def get_value(self, value_name, as_json=False, raise_on_missing=False):
        """
        Get a value by name. Will raise if not found, except a default is given
        :param value_name: The value name to look for
        :param as_json: Whether to normalize the data as JSON or not
        :param raise_on_missing: Will raise exception if value is missing, else will return None
        :return:
        """
        for value in self.iter_values(as_json=as_json):
            if value.name == value_name:
                return value.value

        if raise_on_missing:
            raise RegistryValueNotFoundException('Did not find the value {} on subkey {}'.format(value_name, self.name))
        return None

    def get_values(self, as_json=False):
        return [x for x in self.iter_values(as_json=as_json)]

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

