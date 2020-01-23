import os
from typing import Set

import logbook
from tqdm import tqdm

from regipy.registry import RegistryHive, NKRecord
from regipy.utils import convert_wintime, calculate_sha1

logger = logbook.Logger(__name__)


def get_subkeys_and_timestamps(registry_hive):
    subkeys_and_timestamps = set()
    for subkey in registry_hive.recurse_subkeys():
        subkey_path = subkey.path
        ts = subkey.timestamp
        subkeys_and_timestamps.add((subkey_path, ts))
    return subkeys_and_timestamps


def get_values_from_tuples(value_tuples, value_name_list):
    for value_name, value_data in value_tuples:
        if value_name in value_name_list:
            yield value_name, value_data


def get_timestamp_for_subkeys(registry_hive, subkey_list):
    for subkey_path in subkey_list:
        subkey = registry_hive.get_key(subkey_path)
        yield subkey_path, convert_wintime(subkey.header.last_modified, as_json=True)


def _get_name_value_tuples(subkey: NKRecord) -> Set[tuple]:
    """
    Iterate over value in a subkey and return a set of tuples containing value names and values
    :param subkey: NKRecord to iterate over
    :return: A set of tuples containing value names and values
    """
    values_tuple = set()
    for value in subkey.iter_values(as_json=True):
        if not value.value:
            continue

        if isinstance(value.value, list):
            values_tuple.update({(value.name, x) for x in value.value})
        else:
            values_tuple.add((value.name, value.value))
    return values_tuple


def compare_hives(first_hive_path, second_hive_path, verbose=False):
    # The list will contain tuples, in the following format: (Difference type, first value, second value, description)
    found_differences = []

    # Compare hash, verify they are indeed different
    first_hive_sha1 = calculate_sha1(first_hive_path)
    second_hive_sha1 = calculate_sha1(second_hive_path)

    if first_hive_sha1 == second_hive_sha1:
        logger.info('Hives have the same hash!')
        return found_differences

    # Compare header parameters
    first_registry_hive = RegistryHive(first_hive_path)
    second_registry_hive = RegistryHive(second_hive_path)
    if first_registry_hive.header.hive_bins_data_size != second_registry_hive.header.hive_bins_data_size:
        found_differences.append(('different_hive_bin_data_size', first_registry_hive.header.hive_bins_data_size,
                                  second_registry_hive.header.hive_bins_data_size, ''))

    # Enumerate subkeys for each hive and start comparing
    logger.info('Enumerating subkeys in {}'.format(os.path.basename(first_hive_path)))
    first_hive_subkeys = get_subkeys_and_timestamps(first_registry_hive)

    logger.info('Enumerating subkeys in {}'.format(os.path.basename(second_hive_path)))
    second_hive_subkeys = get_subkeys_and_timestamps(second_registry_hive)

    # Get a set of keys present in one hive and not the other and vice versa
    first_hive_subkey_names = {x[0] for x in first_hive_subkeys if x[0] is not None}
    second_hive_subkey_names = {x[0] for x in second_hive_subkeys if x[0] is not None}

    found_differences.extend(('new_subkey', ts, None, subkey_path) for subkey_path, ts in
                             get_timestamp_for_subkeys(first_registry_hive,
                                                       first_hive_subkey_names - second_hive_subkey_names))

    found_differences.extend(('new_subkey', None, ts, subkey_path) for subkey_path, ts in
                             get_timestamp_for_subkeys(second_registry_hive,
                                                       second_hive_subkey_names - first_hive_subkey_names))

    # Remove duplicate keys from each of the sets
    first_hive_diff_subkeys = first_hive_subkeys - second_hive_subkeys
    second_hive_diff_subkeys = second_hive_subkeys - first_hive_subkeys

    # Find subkeys that exist in both hives, but were modified. Look for new values and subkeys
    for path_1, ts_1 in tqdm(first_hive_diff_subkeys) if verbose else first_hive_diff_subkeys:
        for path_2, ts_2 in tqdm(second_hive_diff_subkeys, leave=False) if verbose else second_hive_diff_subkeys:
            if path_1 and path_1 == path_2 and ts_1 != ts_2:
                first_subkey_nk_record = first_registry_hive.get_key(path_1)
                second_subkey_nk_record = second_registry_hive.get_key(path_2)

                # Compare values between the subkeys
                first_subkey_values = set()
                second_subkey_values = set()

                if first_subkey_nk_record.values_count:
                    first_subkey_values = _get_name_value_tuples(first_subkey_nk_record)

                if second_subkey_nk_record.values_count:
                    second_subkey_values = _get_name_value_tuples(second_subkey_nk_record)

                # If one hive or the other contain values, and they are different, compare values
                if (first_subkey_values or second_subkey_values) and (first_subkey_values != second_subkey_values):
                    first_hive_value_names = set(x[0] for x in first_subkey_values)
                    second_hive_value_names = set(x[0] for x in second_subkey_values)

                    values_in_first_but_not_in_second = first_hive_value_names - second_hive_value_names
                    values_in_second_but_not_in_first = second_hive_value_names - first_hive_value_names

                    # If there are value names that are present in the first subkey but not the second
                    # Iterate over all values in the first subkey
                    # If the value name is one of those that is not on the second subkey, add it to the set
                    if values_in_first_but_not_in_second:
                        found_differences.extend(('new_value', f'{n}: {d} @ {ts_1}', None, path_1) for n, d in
                                                 get_values_from_tuples(first_subkey_values,
                                                                        values_in_first_but_not_in_second))

                    if values_in_second_but_not_in_first:
                        found_differences.extend(('new_value', None, f'{n}: {d} @ {ts_2}', path_1) for n, d in
                                                 get_values_from_tuples(second_subkey_values,
                                                                        values_in_second_but_not_in_first))

                # We do not compare subkeys for each subkey, because we would have detected those.
    return found_differences
