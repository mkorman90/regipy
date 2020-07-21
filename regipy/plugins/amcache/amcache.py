import logbook

from inflection import underscore

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.hive_types import AMCACHE_HIVE_TYPE
from regipy.plugins.plugin import Plugin
from regipy.utils import convert_wintime

logger = logbook.Logger(__name__)

AMCACHE_FIELD_NUMERIC_MAPPINGS = {
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

    def parse_amcache_file_entry(self, subkey):
        entry = {underscore(x.name): x.value for x in subkey.iter_values(as_json=self.as_json)}

        # Sometimes the value names might be numeric instead. Translate them:
        for k, v in AMCACHE_FIELD_NUMERIC_MAPPINGS.items():
            content = entry.pop(k, None)
            if content:
                entry[v] = content

        if 'sha1' in entry:
            entry['sha1'] = entry['sha1'][4:]

        if 'file_id' in entry:
            entry['file_id'] = entry['file_id'][4:]
            if 'sha1' not in entry:
                entry['sha1'] = entry['file_id']

        if 'program_id' in entry:
            entry['program_id'] = entry['program_id'][4:]

        entry['timestamp'] = convert_wintime(subkey.header.last_modified, as_json=self.as_json)

        if 'size' in entry:
            entry['size'] = int(entry['size'], 16) if isinstance(entry['size'], str) else entry['size']

        is_pefile = entry.get('is_pe_file')
        if is_pefile is not None:
            entry['is_pe_file'] = bool(is_pefile)

        is_os_component = entry.get('is_os_component')
        if is_os_component is not None:
            entry['is_os_component'] = bool(is_os_component)

        if entry.get('link_date') == 0:
            entry.pop('link_date')

        for ts_field_name in WIN8_TS_FIELDS:
            ts = entry.pop(ts_field_name, None)
            if ts:
                entry[ts_field_name] = convert_wintime(ts, as_json=self.as_json)

        self.entries.append(entry)

    def run(self):
        logger.info('Started AmCache Plugin...')

        try:
            amcache_file_subkey = self.registry_hive.get_key(r'\Root\File')
        except RegistryKeyNotFoundException:
            logger.info(r'Could not find \Root\File subkey')
            amcache_file_subkey = None

        try:
            amcache_inventory_file_subkey = self.registry_hive.get_key(r'\Root\InventoryApplicationFile')
        except RegistryKeyNotFoundException:
            logger.info(r'Could not find \Root\InventoryApplicationFile subkey')
            amcache_inventory_file_subkey = None

        if amcache_file_subkey:
            for subkey in amcache_file_subkey.iter_subkeys():
                if subkey.header.subkey_count > 0:
                    for file_subkey in subkey.iter_subkeys():
                        self.parse_amcache_file_entry(file_subkey)
                if subkey.header.values_count > 0:
                    self.entries.append(subkey)

        if amcache_inventory_file_subkey:
            for file_subkey in amcache_inventory_file_subkey.iter_subkeys():
                self.parse_amcache_file_entry(file_subkey)
