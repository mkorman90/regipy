import binascii
import datetime as dt
import logging
from collections.abc import Iterator
from typing import Optional

import pytz
from click import progressbar

from regipy import NKRecord, RegistryHive, Subkey
from regipy.utils import MAX_LEN

logger = logging.getLogger(__name__)


def get_filtered_subkeys(
    registry_hive: RegistryHive,
    name_key_entry: NKRecord,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    verbose=False,
    fetch_values=True,
) -> Iterator[Subkey]:
    """
    Get records filtered by the specified timestamps
    :param registry_hive: A RegistryHive object
    :param name_key_entry: A list of paths as strings
    :param start_date: Include only subkeys modified after the specified date
                     in isoformat UTC, for example: 2020-02-18T14:15:00.000000
    :param end_date: Include only subkeys modified before the specified date
                     in isoformat UTC, for example: 2020-02-20T14:15:00.000000
    """
    skipped_entries_count = 0
    start_dt: Optional[dt.datetime] = None
    end_dt: Optional[dt.datetime] = None
    if start_date:
        start_dt = pytz.utc.localize(dt.datetime.fromisoformat(start_date))

    if end_date:
        end_dt = pytz.utc.localize(dt.datetime.fromisoformat(end_date))

    subkey_count = 0
    with progressbar(registry_hive.recurse_subkeys(name_key_entry, fetch_values=False)) as reg_subkeys:
        for subkey_count, subkey in enumerate(reg_subkeys):
            if start_dt and subkey.timestamp < start_dt:
                skipped_entries_count += 1
                logger.debug(f"Skipping entry {subkey} which has a timestamp prior to start_date")
                continue

            if end_dt and subkey.timestamp > end_dt:
                skipped_entries_count += 1
                logger.debug(f"Skipping entry {subkey} which has a timestamp after the end_date")
                continue

            nk = registry_hive.get_key(subkey.path)
            yield Subkey(
                subkey_name=subkey.subkey_name,
                path=subkey.path,
                timestamp=subkey.timestamp,
                values=list(nk.iter_values(as_json=True)) if fetch_values else [],
                values_count=subkey.values_count,
            )
        if subkey_count is not None:
            logger.info(f"{skipped_entries_count} out of {subkey_count} subkeys were filtered out due to timestamp constraints")


def _normalize_subkey_fields(field) -> str:
    result: str
    if isinstance(field, bytes):
        result = binascii.b2a_hex(field[:MAX_LEN]).decode("ascii")
    elif isinstance(field, dt.datetime):
        result = field.isoformat()
    else:
        result = str(field)
    return result
