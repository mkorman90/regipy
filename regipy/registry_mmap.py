import logging
import mmap

import attr

from regipy import boomerang_stream, REGF_HEADER, REGF_HEADER_SIZE, HBin, NKRecord, SUPPORTED_HIVE_TYPES, \
    UnidentifiedHiveException, identify_hive_type, RegistryKeyNotFoundException, LIRecord, RegistryParsingException, \
    convert_wintime, Subkey

logger = logging.getLogger(__name__)


class MemoryMappedRegistryHive:
    CONTROL_SETS = [r'\ControlSet001', r'\ControlSet002']

    def __init__(self, hive_path, hive_type=None, partial_hive_path=None):
        """
        Represents a registry hive
        :param hive_path: Path to the registry hive
        :param hive_type: The hive type can be specified if this is a partial hive,
                          or for some other reason regipy cannot identify the hive type
        :param partial_hive_path: The path from which the partial hive actually starts, for example:
                                  hive_type=ntuser partial_hive_path="/Software" would mean
                                  this is actually a HKCU hive, starting from HKCU/Software
        """

        self.partial_hive_path = None
        self.hive_type = None
        self._stream = None

        with open(hive_path, mode="r", encoding="utf8") as file_obj:
            self._stream = mmap.mmap(file_obj.fileno(), length=0, access=mmap.ACCESS_READ)

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
                logger.info(f'Hive type for {hive_path} was not identified: {self.name}')

        if partial_hive_path:
            self.partial_hive_path = partial_hive_path

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

    def recurse_subkeys(self, nk_record: NKRecord = None, path_root=None, as_json=False, is_init=True, fetch_values=True):
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