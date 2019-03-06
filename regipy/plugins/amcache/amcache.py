import logbook

from inflection import underscore

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import AMCACHE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logbook.Logger(__name__)

WIN8_AMCACHE_MAPPINGS = {
    '0': 'product_name',
    '1': 'company_name',
    '2': 'file_version_number',
    '3': 'language_code',
    '4': 'switchback_context',
    '5': 'file_version',
    '6': 'file_size',
    '7': 'pe_header_hash',
    '8': 'unknown1',
    '9': 'pe_header_checksum',
    'a': 'unknown2',
    'b': 'unknown3',
    'c': 'file_description',
    'd': 'unknown4',
    'f': 'linker_compile_time',
    '10': 'unknown5',
    '11': 'last_modified_timestamp',
    '12': 'created_timestamp',
    '15': 'full_path',
    '16': 'unknown6',
    '17': 'last_modified_timestamp_2',
    '100': 'program_id',
    '101': 'sha1'
}

WIN8_TS_FIELDS = ['last_modified_timestamp', 'created_timestamp', 'last_modified_timestamp_2']


class AmCachePlugin(Plugin):
    NAME = 'amcache'
    DESCRIPTION = 'Parse Amcache'
    COMPATIBLE_HIVE = AMCACHE_HIVE_TYPE

    def run(self):
        logger.info('Started AmCache Plugin...')
        is_win_7_hive = False
        entries = []

        try:
            amcache_subkey = self.registry_hive.get_key(r'\Root\File')
        except RegistryKeyNotFoundException:
            amcache_subkey = self.registry_hive.get_key(r'\Root\InventoryApplicationFile')
            is_win_7_hive = True

        if is_win_7_hive:
            for subkey in amcache_subkey.iter_subkeys():
                entry = {underscore(x.name): x.value for x in subkey.iter_values(as_json=self.as_json)}
                entry['program_id'] = entry['program_id'][4:]
                entry['file_id'] = entry['file_id'][4:]
                entry['sha1'] = entry['file_id']
                entry['timestamp'] = convert_wintime(subkey.header.last_modified, as_json=self.as_json)
                entry['size'] = int(entry['size'], 16) if isinstance(entry['size'], str) else entry['size']

                entry['is_pe_file'] = bool(entry['is_pe_file'])
                entry['is_os_component'] = bool(entry['is_os_component'])

                if entry['link_date'] == 0:
                    entry.pop('link_date')

                entry['type'] = 'win_7_amcache'
                entries.append(entry)
        else:
            for subkey in amcache_subkey.iter_subkeys():
                for file_subkey in subkey.iter_subkeys():
                    entry = {x.name: x.value for x in file_subkey.iter_values(as_json=self.as_json)}
                    entry['timestamp'] = convert_wintime(file_subkey.header.last_modified, as_json=self.as_json)

                    for k, v in WIN8_AMCACHE_MAPPINGS.items():
                        content = entry.pop(k, None)
                        if content:
                            entry[v] = content

                    entry['sha1'] = entry['sha1'][4:]
                    entry['program_id'] = entry['program_id'][4:]
                    entry['type'] = 'win_8+_amcache'

                    for ts_field_name in WIN8_TS_FIELDS:
                        ts = entry.pop(ts_field_name, None)
                        if ts:
                            entry[ts_field_name] = convert_wintime(ts, as_json=self.as_json)
                    entries.append(entry)
        return entries
