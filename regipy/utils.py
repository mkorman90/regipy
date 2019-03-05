import attr
import binascii
import hashlib
import sys

from contextlib import contextmanager
import datetime as dt
from io import TextIOWrapper

import logbook
import pytz

from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException, RegipyGeneralException, \
    UnidentifiedHiveException
from regipy.hive_types import NTUSER_HIVE_TYPE, SYSTEM_HIVE_TYPE, AMCACHE_HIVE_TYPE, SOFTWARE_HIVE_TYPE, \
    SAM_HIVE_TYPE

logger = logbook.Logger(__name__)

# Max size of string to return when as_json=True
MAX_LEN = 128


def calculate_sha1(file_path):
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(1024 ** 2)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()


def calculate_xor32_checksum(b: bytes) -> int:
    """
    Calculate xor32 checksum from buffer
    :param b: buffer
    :return: The calculated checksum
    """
    checksum = 0
    if len(b) % 4 != 0:
        raise RegipyGeneralException(f'Buffer must be multiples of four, {len(b)} length buffer given')

    for i in range(0, len(b), 4):
        checksum = (b[i] + (b[i + 1] << 0x08) + (b[i + 2] << 0x10) + (b[i + 3] << 0x18)) ^ checksum
    return checksum


@contextmanager
def boomerang_stream(stream: TextIOWrapper) -> TextIOWrapper:
    """
    Yield a stream that goes back to the original offset after exiting the "with" context
    :param stream: The stream
    """
    current_offset = stream.tell()
    yield stream
    stream.seek(current_offset)


def convert_wintime(wintime: int, as_json=False) -> dt.datetime:
    """
    Get an integer containing a FILETIME date
    :param wintime: integer representing a FILETIME timestamp
    :param as_json: whether to return the date as string or not
    :return: datetime
    """
    # http://stackoverflow.com/questions/4869769/convert-64-bit-windows-date-time-in-python
    us = wintime / 10
    try:
        date = dt.datetime(1601, 1, 1, tzinfo=pytz.utc) + dt.timedelta(microseconds=us)
    except OverflowError:
        # If date is too big, it is probably corrupted' let's return the smalles possible windows timestamp.
        date = dt.datetime(1601, 1, 1, tzinfo=pytz.utc)
    return date.isoformat() if as_json else date


def get_subkey_values_from_list(registry_hive, entries_list, as_json=False):
    """
    Return a list of registry subkeys given a list of paths
    :param registry_hive: A RegistryHive object
    :param entries_list: A list of paths as strings
    :param as_json: Whether to return the subkey as json
    :return: A dict with each subkey and its values
    """
    result = {}
    for path in entries_list:
        try:
            subkey = registry_hive.get_key(path)
        except (RegistryKeyNotFoundException, NoRegistrySubkeysException) as ex:
            logger.debug('Could not find subkey: {} ({})'.format(path, ex))
            continue
        ts = convert_wintime(subkey.header.last_modified, as_json=as_json)

        values = []
        if subkey.values_count:
            if as_json:
                values = [attr.asdict(x) for x in subkey.iter_values(as_json=as_json)]
            else:
                values = list(subkey.iter_values(as_json=as_json))

        if subkey.values_count:
            result[path] = {
                'timestamp': ts,
                'values': values
            }
    return result


def identify_hive_type(name: str) -> str:
    hive_name = name.lower()
    if hive_name.endswith('ntuser.dat'):
        return NTUSER_HIVE_TYPE
    elif hive_name == SYSTEM_HIVE_TYPE:
        return SYSTEM_HIVE_TYPE
    elif hive_name == '\\appcompat\\programs\\amcache.hve':
        return AMCACHE_HIVE_TYPE
    elif hive_name.endswith('system32\\config\\software'):
        return SOFTWARE_HIVE_TYPE
    elif hive_name == r'\systemroot\system32\config\sam':
        return SAM_HIVE_TYPE
    else:
        raise UnidentifiedHiveException(f'Could not identify hive: {name}')


def try_decode_binary(data, as_json=False, max_len=MAX_LEN):
    try:
        value = data.decode('utf-16-le').rstrip('\x00')
    except UnicodeDecodeError:
        try:
            value = data.decode().rstrip('\x00')
        except:
            value = binascii.b2a_hex(data).decode()[:max_len] if as_json else data
    return value


def _get_log_handlers(verbose):
    return [logbook.StreamHandler(sys.stdout, level=logbook.DEBUG if verbose else logbook.INFO, bubble=True)]
