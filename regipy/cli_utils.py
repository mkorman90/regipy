import binascii
import logging
import datetime as dt

import pytz
from click import progressbar
from typing import Iterator

from regipy import RegistryHive, NKRecord, Subkey
from regipy.utils import MAX_LEN


logger = logging.getLogger(__name__)

def get_filtered_subkeys(registry_hive: RegistryHive, name_key_entry: NKRecord, start_date: str = None, end_date: str = None, verbose=False, fetch_values=True) -> Iterator[NKRecord]: 
    """
    Get records filtered by the specified timestamps
    :param registry_hive: A RegistryHive object
    :param name_key_entry: A list of paths as strings
    :param start_date: Include only subkeys modified after the specified date, in isoformat UTC, for example: 2020-02-18T14:15:00.000000
    :param end_date: Include only subkeys modified before the specified date, in isoformat UTC, for example: 2020-02-20T14:15:00.000000
    """
    skipped_entries_count = 0
    if start_date:
        start_date = pytz.utc.localize(dt.datetime.fromisoformat(start_date))
    
    if end_date:
        end_date = pytz.utc.localize(dt.datetime.fromisoformat(end_date))


    with progressbar(registry_hive.recurse_subkeys(name_key_entry, fetch_values=False)) as reg_subkeys:
        for subkey_count, subkey in enumerate(reg_subkeys): 
            if start_date:
                if subkey.timestamp < start_date:
                    skipped_entries_count += 1
                    logger.debug(f"Skipping entry {subkey} which has a timestamp prior to start_date")
                    continue

            if end_date:
                if subkey.timestamp > end_date:
                    skipped_entries_count += 1
                    logger.debug(f"Skipping entry {subkey} which has a timestamp after the end_date")
                    continue

            nk = registry_hive.get_key(subkey.path)
            yield Subkey(subkey_name=subkey.subkey_name, path=subkey.path,
                             timestamp=subkey.timestamp, values=list(nk.iter_values(as_json=True)) if fetch_values else [],
                             values_count=subkey.values_count)
        logger.info(f"{skipped_entries_count} out of {subkey_count} subkeys were filtered out due to timestamp constrains")

def _normalize_subkey_fields(field) -> str:
    if isinstance(field, bytes):
        return binascii.b2a_hex(field[:MAX_LEN])
    elif isinstance(field, dt.datetime):
        return field.isoformat()
    return field
