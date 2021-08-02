import binascii
import datetime as dt
import hashlib
import logging
import sys

from typing import Generator, Union

from contextlib import contextmanager
from io import TextIOWrapper
from struct import unpack

import attr
import pytz

from regipy.exceptions import NoRegistrySubkeysException, RegistryKeyNotFoundException, RegipyGeneralException, \
    UnidentifiedHiveException, NtSidDecodingException
from regipy.hive_types import NTUSER_HIVE_TYPE, SYSTEM_HIVE_TYPE, AMCACHE_HIVE_TYPE, SOFTWARE_HIVE_TYPE, \
    SAM_HIVE_TYPE, SECURITY_HIVE_TYPE

logger = logging.getLogger(__name__)

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
def boomerang_stream(stream: TextIOWrapper) -> Generator[TextIOWrapper, None, None]:
    """
    Yield a stream that goes back to the original offset after exiting the "with" context
    :param stream: The stream
    """
    current_offset = stream.tell()
    yield stream
    stream.seek(current_offset)


def convert_filetime(dw_low_date_time, dw_high_date_time):
    """
    """
    if dw_high_date_time is None or dw_low_date_time is None:
        return None
    try:
        date = dt.datetime(1601, 1, 1, 0, 0, 0)
        temp_time = dw_high_date_time
        temp_time <<= 32
        temp_time |= dw_low_date_time
        date = pytz.utc.localize(date + dt.timedelta(microseconds=temp_time / 10))
        return date.isoformat()
    except OverflowError:
        return None


def convert_wintime(wintime: int, as_json=False) -> Union[dt.datetime, str]:
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
        # If date is too big, it is probably corrupted' let's return the smallest possible windows timestamp.
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
    elif hive_name.endswith('system32\\config\\software'):
        return SOFTWARE_HIVE_TYPE
    elif hive_name == r'\systemroot\system32\config\sam':
        return SAM_HIVE_TYPE
    elif hive_name == r'emroot\system32\config\security':
        return SECURITY_HIVE_TYPE
    elif 'amcache' in hive_name.lower():
        return AMCACHE_HIVE_TYPE
    else:
        raise UnidentifiedHiveException(f'Could not identify hive: {name}')


def try_decode_binary(data, as_json=False, max_len=MAX_LEN):
    try:
        value = data.decode('utf-16-le').rstrip('\x00')
    except UnicodeDecodeError:
        try:
            value = data.decode().rstrip('\x00')
        except:
            value = binascii.b2a_hex(data).decode() if as_json else data

    # If we the data should be exported as json, trim the value length
    if as_json:
        value = value[:max_len]

    return value


def decode_binary_sid(data: bytes, strip_rid: bool = False) -> str:
    """
    Decodes raw binary data into a Windows NT SID (Security Identifier) string.

    Re-implements `ConvertSidToStringSid()` function from the Windows API.
    See `https://devblogs.microsoft.com/oldnewthing/20040315-00/?p=40253`

    Optionally strips the RID (relative ID) component (the last dashed number)
    from the SID string when the `strip_rid` parameter is set.
    """

    # S-1-5-...
    if data[0] != 0x01 or data[2:8] != b'\x00\x00\x00\x00\x00\x05':
        raise NtSidDecodingException("Not a valid Windows NT SID")

    # N (number of SID dashes minus two)
    num_words = data[1]

    if len(data) != 4*num_words + 8:
        raise NtSidDecodingException("Unexpected binary SID length")

    if strip_rid:
        # The fifth 32-bit component word encodes the RID (relative ID)
        num_words = 4

    if num_words == 5:
        # Machine SID + RID
        components = unpack("<5L", data[8:28])
        return "S-1-5-%d-%d-%d-%d-%d" % components

    if num_words == 4:
        # Machine SID only
        components = unpack("<4L", data[8:24])
        return "S-1-5-%d-%d-%d-%d" % components

    raise NtSidDecodingException("Unexpected SID component count")


def _setup_logging(verbose):
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG if verbose else logging.INFO,
    )
