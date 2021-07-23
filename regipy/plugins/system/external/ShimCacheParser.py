# Andrew Davis, andrew.davis@mandiant.com
# Copyright 2012 Mandiant
#
# Mandiant licenses this file to you under the Apache License, Version
# 2.0 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
#
# Identifies and parses Application Compatibility Shim Cache entries for forensic data.


# Original Mandiant shim cache parser, ported to Python 3
# Identifies and parses Application Compatibility Shim Cache entries for forensic data.

import datetime
import io as sio
import struct

import logging
import pytz

CACHE_MAGIC_NT5_2 = 0xbadc0ffe
CACHE_HEADER_SIZE_NT5_2 = 0x8
NT5_2_ENTRY_SIZE32 = 0x18
NT5_2_ENTRY_SIZE64 = 0x20

# Values used by Windows 6.1 (Win7 and Server 2008 R2)
CACHE_MAGIC_NT6_1 = 0xbadc0fee
CACHE_HEADER_SIZE_NT6_1 = 0x80
NT6_1_ENTRY_SIZE32 = 0x20
NT6_1_ENTRY_SIZE64 = 0x30
CSRSS_FLAG = 0x2

# Values used by Windows 5.1 (WinXP 32-bit)
WINXP_MAGIC32 = 0xdeadbeef
WINXP_HEADER_SIZE32 = 0x190
WINXP_ENTRY_SIZE32 = 0x228
MAX_PATH = 520

# Values used by Windows 8
WIN8_STATS_SIZE = 0x80
WIN8_MAGIC = b'00ts'

# Magic value used by Windows 8.1
WIN81_MAGIC = b'10ts'

# Values used by Windows 10
WIN10_STATS_SIZE = 0x30
WIN10_MAGIC = b'10ts'
CACHE_HEADER_SIZE_NT6_4 = 0x30
CACHE_MAGIC_NT6_4 = 0x30

BAD_ENTRY_DATA = 'N/A'
G_VERBOSE = False
G_USE_BOM = False
OUTPUT_HEADER = ["Last Modified", "Last Update", "Path", "File Size", "Exec Flag"]

logger = logging.getLogger(__name__)

# Shim Cache format used by Windows 5.2 and 6.0 (Server 2003 through Vista/Server 2008)
class CacheEntryNt5(object):
    def __init__(self, is_32_bit, data=None):
        self.w_length = None
        self.w_maximum_length = None
        self.offset = None
        self.dw_low_date_time = None
        self.dw_high_date_time = None
        self.dw_file_size_low = None
        self.dw_file_size_high = None
        self.is_32_bit = is_32_bit
        if data is not None:
            self.update(data)

    def update(self, data):
        if self.is_32_bit:
            entry = struct.unpack('<2H 3L 2L', data)
        else:
            entry = struct.unpack('<2H 4x Q 2L 2L', data)
        self.w_length = entry[0]
        self.w_maximum_length = entry[1]
        self.offset = entry[2]
        self.dw_low_date_time = entry[3]
        self.dw_high_date_time = entry[4]
        self.dw_file_size_low = entry[5]
        self.dw_file_size_high = entry[6]

    def size(self):

        if self.is_32_bit:
            return NT5_2_ENTRY_SIZE32
        else:
            return NT5_2_ENTRY_SIZE64


# Shim Cache format used by Windows 6.1 (Win7 through Server 2008 R2).
class CacheEntryNt6(object):
    def __init__(self, is_32_bit, data=None):
        self.w_length = None
        self.w_maximum_length = None
        self.offset = None
        self.dw_low_date_time = None
        self.dw_high_date_time = None
        self.file_flags = None
        self.flags = None
        self.blob_size = None
        self.blob_offset = None
        self.is_32_bit = is_32_bit
        if data is not None:
            self.update(data)

    def update(self, data):
        if self.is_32_bit:
            entry = struct.unpack('<2H 7L', data)
        else:
            entry = struct.unpack('<2H 4x Q 4L 2Q', data)
        self.w_length = entry[0]
        self.w_maximum_length = entry[1]
        self.offset = entry[2]
        self.dw_low_date_time = entry[3]
        self.dw_high_date_time = entry[4]
        self.file_flags = entry[5]
        self.flags = entry[6]
        self.blob_size = entry[7]
        self.blob_offset = entry[8]

    def size(self):
        if self.is_32_bit:
            return NT6_1_ENTRY_SIZE32
        else:
            return NT6_1_ENTRY_SIZE64


# Convert FILETIME to datetime.
# Based on http://code.activestate.com/recipes/511425-filetime-to-datetime/
def convert_filetime(dw_low_date_time, dw_high_date_time):
    try:
        date = datetime.datetime(1601, 1, 1, 0, 0, 0)
        temp_time = dw_high_date_time
        temp_time <<= 32
        temp_time |= dw_low_date_time
        return pytz.utc.localize(date + datetime.timedelta(microseconds=temp_time / 10))
    except OverflowError:
        return None


# Return a unique list while preserving ordering.
def unique_list(li):
    ret_list = []
    for entry in li:
        if entry not in ret_list:
            ret_list.append(entry)
    return ret_list


# Read the Shim Cache format, return a list of last modified dates/paths.
def get_shimcache_entries(cachebin, as_json=False):

    if len(cachebin) < 16:
        # Data size less than minimum header size.
        return None

    # Get the format type
    magic = struct.unpack("<L", cachebin[0:4])[0]

    # This is a Windows 2k3/Vista/2k8 Shim Cache format,
    if magic == CACHE_MAGIC_NT5_2:

        # Shim Cache types can come in 32-bit or 64-bit formats. We can
        # determine this because 64-bit entries are serialized with u_int64
        # pointers. This means that in a 64-bit entry, valid UNICODE_STRING
        # sizes are followed by a NULL DWORD. Check for this here.
        test_size = struct.unpack("<H", cachebin[8:10])[0]
        test_max_size = struct.unpack("<H", cachebin[10:12])[0]
        if (test_max_size - test_size == 2 and
                struct.unpack("<L", cachebin[12:16])[0]) == 0:
            logger.info("[+] Found 64bit Windows 2k3/Vista/2k8 Shim Cache data...")
            entry = CacheEntryNt5(False)
            yield from read_nt5_entries(cachebin, entry, as_json=as_json)

        # Otherwise it's 32-bit data.
        else:
            logger.info("[+] Found 32bit Windows 2k3/Vista/2k8 Shim Cache data...")
            entry = CacheEntryNt5(True)
            yield from read_nt5_entries(cachebin, entry, as_json=as_json)

    # This is a Windows 7/2k8-R2 Shim Cache.
    elif magic == CACHE_MAGIC_NT6_1:
        test_size = (struct.unpack("<H", cachebin[CACHE_HEADER_SIZE_NT6_1:CACHE_HEADER_SIZE_NT6_1 + 2])[0])
        test_max_size = (struct.unpack("<H", cachebin[CACHE_HEADER_SIZE_NT6_1 + 2:CACHE_HEADER_SIZE_NT6_1 + 4])[0])

        # Shim Cache types can come in 32-bit or 64-bit formats.
        # We can determine this because 64-bit entries are serialized with
        # u_int64 pointers. This means that in a 64-bit entry, valid
        # UNICODE_STRING sizes are followed by a NULL DWORD. Check for this here.
        if (test_max_size - test_size == 2 and
                struct.unpack("<L", cachebin[CACHE_HEADER_SIZE_NT6_1 + 4:CACHE_HEADER_SIZE_NT6_1 + 8])[0]) == 0:
            logger.info("[+] Found 64bit Windows 7/2k8-R2 Shim Cache data...")
            entry = CacheEntryNt6(False)
            yield from read_nt6_entries(cachebin, entry, as_json=as_json)
        else:
            logger.info("[+] Found 32bit Windows 7/2k8-R2 Shim Cache data...")
            entry = CacheEntryNt6(True)
            yield from read_nt6_entries(cachebin, entry, as_json=as_json)

    # This is WinXP cache data
    elif magic == WINXP_MAGIC32:
        logger.info("[+] Found 32bit Windows XP Shim Cache data...")
        yield from read_winxp_entries(cachebin, as_json=as_json)

    # Check the data set to see if it matches the Windows 8 format.
    elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE + 4] == WIN8_MAGIC:
        logger.info("[+] Found Windows 8/2k12 Apphelp Cache data...")
        yield from read_win8_entries(cachebin, WIN8_MAGIC, as_json=as_json)

    # Windows 8.1 will use a different magic dword, check for it
    elif len(cachebin) > WIN8_STATS_SIZE and cachebin[WIN8_STATS_SIZE:WIN8_STATS_SIZE + 4] == WIN81_MAGIC:
        logger.info("[+] Found Windows 8.1 Apphelp Cache data...")
        yield from read_win8_entries(cachebin, WIN81_MAGIC, as_json=as_json)

    # Windows 10 will use a different magic dword, check for it
    elif len(cachebin) > WIN10_STATS_SIZE and cachebin[WIN10_STATS_SIZE:WIN10_STATS_SIZE + 4] == WIN10_MAGIC:
        logger.info("[+] Found Windows 10 Apphelp Cache data...")
        yield from read_win10_entries(cachebin, WIN10_MAGIC, as_json=as_json)

    # Windows 10 creators update moved the damn magic 4 bytes forward...
    elif len(cachebin) > WIN10_STATS_SIZE and cachebin[WIN10_STATS_SIZE + 4:WIN10_STATS_SIZE + 8] == WIN10_MAGIC:
        logger.info("[+] Found Windows 10 Apphelp Cache data... (creators update)")
        yield from read_win10_entries(cachebin, WIN10_MAGIC, creators_update=True, as_json=as_json)

    else:
        raise Exception('Got an unrecognized magic value of 0x{:x}... bailing'.format(magic))


# Read Windows 8/2k12/8.1 Apphelp Cache entry formats.
def read_win8_entries(bin_data, ver_magic, as_json=False):

    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    cache_data = bin_data[WIN8_STATS_SIZE:]

    data = sio.BytesIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        # Read in the entry metadata
        # Note: the crc32 hash is of the cache entry data
        magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)

        # Check the magic tag
        if magic != ver_magic:
            raise Exception('Invalid version magic tag found: {}'.format(struct.unpack('I', magic)[0]))

        entry_data = sio.BytesIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack('<H', entry_data.read(2))[0]
        if path_len == 0:
            path = 'None'
        else:
            path = entry_data.read(path_len).decode('utf-16le', 'replace')

        # Check for package data
        package_len = struct.unpack('<H', entry_data.read(2))[0]
        if package_len > 0:
            # Just skip past the package data if present (for now)
            entry_data.seek(package_len, 1)

        # Read the remaining entry data
        flags, unk_1, low_datetime, high_datetime, unk_2 = struct.unpack('<LLLLL', entry_data.read(20))

        # Check the flag set in CSRSS
        if flags & CSRSS_FLAG:
            exec_flag = 'True'
        else:
            exec_flag = 'False'

        last_mod_date = convert_filetime(low_datetime, high_datetime)

        yield {
            'last_mod_date': last_mod_date.isoformat() if as_json else last_mod_date,
            'path': path,
            'exec_flag': exec_flag
        }


# Read Windows 10 Apphelp Cache entry format
def read_win10_entries(bin_data, ver_magic, creators_update=False, as_json=False):

    entry_meta_len = 12
    entry_list = []

    # Skip past the stats in the header
    if creators_update:
        cache_data = bin_data[WIN10_STATS_SIZE + 4:]
    else:
        cache_data = bin_data[WIN10_STATS_SIZE:]

    data = sio.BytesIO(cache_data)
    while data.tell() < len(cache_data):
        header = data.read(entry_meta_len)
        # Read in the entry metadata
        # Note: the crc32 hash is of the cache entry data
        magic, crc32_hash, entry_len = struct.unpack('<4sLL', header)

        # Check the magic tag
        if magic != ver_magic:
            raise Exception('Invalid version magic tag found: {}'.format(struct.unpack('<I', magic)[0]))

        entry_data = sio.BytesIO(data.read(entry_len))

        # Read the path length
        path_len = struct.unpack('<H', entry_data.read(2))[0]
        if path_len == 0:
            path = 'None'
        else:
            path = entry_data.read(path_len).decode('utf-16le', 'replace')

        # Read the remaining entry data
        low_datetime, high_datetime = struct.unpack('<LL', entry_data.read(8))

        # Skip the unrecognized Microsoft App entry format for now
        if not (low_datetime+high_datetime):
            continue
        else:
            last_mod_date = convert_filetime(low_datetime, high_datetime)

        yield {
            'last_mod_date': last_mod_date.isoformat() if as_json else last_mod_date,
            'path': path
        }


# Read Windows 2k3/Vista/2k8 Shim Cache entry formats.
def read_nt5_entries(bin_data, entry, as_json=False):
    entry_list = []
    contains_file_size = False
    entry_size = entry.size()

    num_entries = struct.unpack('<L', bin_data[4:8])[0]
    if num_entries == 0:
        return None

    # On Windows Server 2008/Vista, the filesize is swapped out of this
    # structure with two 4-byte flags. Check to see if any of the values in
    # "dwFileSizeLow" are larger than 2-bits. This indicates the entry contained file sizes.
    for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size) + CACHE_HEADER_SIZE_NT5_2,
                        entry_size):

        entry.update(bin_data[offset:offset + entry_size])

        if entry.dw_file_size_low > 3:
            contains_file_size = True
            break

    # Now grab all the data in the value.
    for offset in range(CACHE_HEADER_SIZE_NT5_2, (num_entries * entry_size) + CACHE_HEADER_SIZE_NT5_2,
                        entry_size):

        entry.update(bin_data[offset:offset + entry_size])

        last_mod_date = convert_filetime(entry.dw_low_date_time, entry.dw_high_date_time)
        path = bin_data[entry.offset:entry.offset + entry.w_length].decode('utf-16le', 'replace')

        # It contains file size data.
        exec_flag = None
        if contains_file_size:
            yield {
                'last_mod_date': last_mod_date.isoformat() if as_json else last_mod_date,
                'path': path,
                'file_size': entry.dw_file_size_low
            }

        # It contains flags.
        else:
            # Check the flag set in CSRSS
            if entry.dw_file_size_low & CSRSS_FLAG:
                exec_flag = 'True'
            else:
                exec_flag = 'False'

            yield {
                'last_mod_date': last_mod_date.isoformat() if as_json else last_mod_date,
                'path': path,
                'exec_flag': exec_flag
            }


# Read the Shim Cache Windows 7/2k8-R2 entry format,
# return a list of last modifed dates/paths.
def read_nt6_entries(bin_data, entry, as_json=False):
    entry_size = entry.size()
    num_entries = struct.unpack('<L', bin_data[4:8])[0]

    if num_entries == 0:
        return None

    # Walk each entry in the data structure.
    for offset in range(CACHE_HEADER_SIZE_NT6_1, num_entries * entry_size + CACHE_HEADER_SIZE_NT6_1, entry_size):

        entry.update(bin_data[offset:offset + entry_size])
        last_mod_date = convert_filetime(entry.dw_low_date_time, entry.dw_high_date_time)
        path = bin_data[entry.offset:entry.offset + entry.w_length].decode('utf-16le', 'replace')

        # Test to see if the file may have been executed.
        if entry.file_flags & CSRSS_FLAG:
            exec_flag = 'True'
        else:
            exec_flag = 'False'

        yield {
            'last_mod_date': last_mod_date.isoformat() if as_json else last_mod_date,
            'path': path,
            'exec_flag': exec_flag
        }


# Read the WinXP Shim Cache data. Some entries can be missing data but still
# contain useful information, so try to get as much as we can.
def read_winxp_entries(bin_data, as_json=False):
    entry_list = []

    num_entries = struct.unpack('<L', bin_data[8:12])[0]
    if num_entries == 0:
        return None

    for offset in range(WINXP_HEADER_SIZE32,
                        (num_entries * WINXP_ENTRY_SIZE32) + WINXP_HEADER_SIZE32, WINXP_ENTRY_SIZE32):
        # No size values are included in these entries, so search for utf-16 terminator.
        path_len = bin_data[offset:offset + (MAX_PATH + 8)].find(b'\x00\x00')

        # if path is corrupt, procede to next entry.
        if path_len == 0:
            continue
        path = bin_data[offset:offset + path_len + 1].decode('utf-16le')

        if len(path) == 0:
            continue

        entry_data = (offset + (MAX_PATH + 8))

        # Get last mod time.
        last_mod_time = struct.unpack('<2L', bin_data[entry_data:entry_data + 8])
        last_mod_time = convert_filetime(last_mod_time[0],last_mod_time[1])

        # Get last file size.
        file_size = struct.unpack('<2L', bin_data[entry_data + 8:entry_data + 16])[0]
        if file_size == 0:
            file_size = BAD_ENTRY_DATA

        # Get last update time.
        exec_time = struct.unpack('<2L', bin_data[entry_data + 16:entry_data + 24])
        exec_time = convert_filetime(exec_time[0],exec_time[1])

        yield {
            'last_mod_time': last_mod_time.isoformat() if as_json else last_mod_time,
            'exec_time': exec_time.isoformat() if as_json else exec_time,
            'path': path,
            'file_size': file_size
        }


def parse_output(output):
    new_output_list = list()
    for row in output:
        exec_flag = False
        if row[4] == 'True':
            exec_flag = True
        entry = {'last_mod_date': row[0], 'last_update': row[1], 'path': row[2], 'file_size': row[3],
                 'exec_flag': exec_flag}
        new_output_list.append(entry)
    return new_output_list
