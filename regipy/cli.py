import binascii
import csv
import json
import logging
import os
import time
from typing import Generator, Iterator 


import attr
import click
import pytz 
from tabulate import tabulate

from regipy.plugins.plugin import PLUGINS
from regipy.recovery import apply_transaction_logs
from regipy.regdiff import compare_hives
from regipy.plugins.utils import run_relevant_plugins
from regipy.registry import NKRecord, RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException
from regipy.utils import calculate_xor32_checksum, _setup_logging
from regipy.cli_utils import get_filtered_subkeys, _normalize_subkey_fields

logger = logging.getLogger(__name__)


@click.command()
@click.argument('hive_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True)
@click.option('-v', '--verbose', is_flag=True, default=True, help='Verbosity')
def parse_header(hive_path, verbose):
    _setup_logging(verbose=verbose)
    registry_hive = RegistryHive(hive_path)

    click.secho(tabulate(registry_hive.header.items(), tablefmt='fancy_grid'))

    if registry_hive.header.primary_sequence_num != registry_hive.header.secondary_sequence_num:
        click.secho('Hive is not clean! You should apply transaction logs', fg='red')

    calculated_checksum = calculate_xor32_checksum(registry_hive._stream.read(508))
    if registry_hive.header.checksum != calculated_checksum:
        click.secho('Hive is not clean! Header checksum does not match', fg='red')


@click.command()
@click.argument('hive_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True)
@click.option('-o', 'output_path', type=click.Path(exists=False, dir_okay=False, resolve_path=True), required=False)
@click.option('-p', '--registry-path', help='A registry path to start iterating from')
@click.option('-t', '--timeline', is_flag=True, default=False, help='Create a CSV timeline instead')
@click.option('-l', '--hive-type', type=click.STRING, required=False,
              help='Specify a hive type, if it could not be identified for some reason')
@click.option('-r', '--partial_hive_path', type=click.STRING, required=False,
              help='The path from which the partial hive actually starts, for example: -t ntuser -r "/Software" '
                   'would mean this is actually a HKCU hive, starting from HKCU/Software')
@click.option('-v', '--verbose', is_flag=True, default=False, help='Verbosity')
@click.option('-d', '--do-not-fetch-values', is_flag=True, default=False, help='Not fetching the values for each subkey '
                                                                              'makes the iteration way faster. Values count will still be returned')
@click.option('-s', '--start-date', type=click.STRING, required=False,
              help='If "-s" was specified, fetch only values for subkeys starting this timestamp in isoformat')
@click.option('-e', '--end-date', type=click.STRING, required=False,
              help='If "-e" was specified, fetch only values for subkeys until this timestamp in isoformat')
def registry_dump(hive_path, output_path, registry_path, timeline, hive_type, partial_hive_path, verbose, do_not_fetch_values, start_date, end_date):
    _setup_logging(verbose=verbose)
    registry_hive = RegistryHive(hive_path, hive_type=hive_type, partial_hive_path=partial_hive_path)

    start_time = time.monotonic()

    if registry_path:
        try:
            name_key_entry = registry_hive.get_key(registry_path)
        except RegistryKeyNotFoundException as ex:
            logger.debug('Did not find the key: {}'.format(ex))
            return
    else:
        name_key_entry = registry_hive.root

    if timeline and not output_path:
        click.secho('You must provide an output path if choosing timeline output!', fg='red')
        return

    if output_path:
        with open(output_path, 'w') as output_file:
            if timeline:
                csvwriter = csv.DictWriter(output_file, delimiter=',',
                                           quotechar='"', quoting=csv.QUOTE_MINIMAL,
                                           fieldnames=['timestamp', 'subkey_name', 'values_count', 'values'])
                csvwriter.writeheader()

            for subkey_count, entry in enumerate(get_filtered_subkeys(registry_hive, name_key_entry, fetch_values=not do_not_fetch_values, start_date=start_date, end_date=end_date)):
                if timeline:
                    csvwriter.writerow({
                        'subkey_name': entry.path,
                        'timestamp': entry.timestamp,
                        'values_count': entry.values_count,
                        'values': entry.values
                    })
                else:
                    output_file.write(json.dumps(attr.asdict(entry,), separators=(',', ':',), default=_normalize_subkey_fields))
                    output_file.write('\n')
    else:
        for subkey_count, entry in enumerate(registry_hive.recurse_subkeys(name_key_entry, as_json=True, fetch_values=not do_not_fetch_values)):
            click.secho(json.dumps(attr.asdict(entry), indent=4))

    click.secho(f"Completed in {time.monotonic() - start_time}s ({subkey_count} subkeys enumerated)")


@click.command()
@click.argument('hive_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True)
@click.option('-o', 'output_path', type=click.Path(exists=False, dir_okay=False, resolve_path=True), required=True,
              help='Output path for plugins result')
@click.option('-p', '--plugins', type=click.STRING, required=False,
              help='A plugin or list of plugins to execute command separated')
@click.option('-t', '--hive-type', type=click.STRING, required=False,
              help='Specify a hive type, if it could not be identified for some reason')
@click.option('-r', '--partial_hive_path', type=click.STRING, required=False,
              help='The path from which the partial hive actually starts, for example: -t ntuser -r "/Software" '
                   'would mean this is actually a HKCU hive, starting from HKCU/Software')
@click.option('-v', '--verbose', is_flag=True, default=False, help='Verbosity')
def run_plugins(hive_path, output_path, plugins, hive_type, partial_hive_path, verbose):
    _setup_logging(verbose=verbose)
    registry_hive = RegistryHive(hive_path, hive_type=hive_type, partial_hive_path=partial_hive_path)
    click.secho('Loaded {} plugins'.format(len(PLUGINS)), fg='white')

    if plugins:
        plugin_names = {x.NAME for x in PLUGINS}
        plugins = plugins.split(',')
        plugins = set(plugins)
        if not plugins.issubset(plugin_names):
            click.secho('Invalid plugin names given: {}'.format(','.join(set(plugins) - plugin_names)), fg='red')
            click.secho('Use --help or -h to get list of plugins and their descriptions', fg='red')
            return

    # Run relevant plugins
    plugin_results = run_relevant_plugins(registry_hive, as_json=True, plugins=plugins)

    # If output path was set, dump results to disk
    if output_path:
        with open(output_path, 'w') as f:
            f.write(json.dumps(plugin_results, indent=4))
    else:
        print(json.dumps(plugin_results, indent=4))
    click.secho('Finished: {}/{} plugins matched the hive type'.format(len(plugin_results), len(PLUGINS)),
                fg='green')


@click.command()
def list_plugins():
    click.secho(tabulate([(x.NAME, x.COMPATIBLE_HIVE, x.DESCRIPTION) for x in PLUGINS],
                         headers=['Plugin Name', 'Compatible hive', 'Description']))


@click.command()
@click.argument('first_hive_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True)
@click.argument('second_hive_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True)
@click.option('-o', 'output_path', type=click.Path(exists=False, dir_okay=False, resolve_path=True), required=False)
@click.option('-v', '--verbose', is_flag=True, default=False, help='Verbosity')
def reg_diff(first_hive_path, second_hive_path, output_path, verbose):
    _setup_logging(verbose=verbose)
    REGDIFF_HEADERS = ['difference', 'first_hive', 'second_hive', 'description']

    found_differences = compare_hives(first_hive_path, second_hive_path, verbose=verbose)
    click.secho('Comparing {} vs {}'.format(os.path.basename(first_hive_path), os.path.basename(second_hive_path)))

    if output_path:
        with open(output_path, 'w') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter='|', quoting=csv.QUOTE_MINIMAL)
            csvwriter.writerow(REGDIFF_HEADERS)
            for difference in found_differences:
                csvwriter.writerow(difference)
    else:
        click.secho(tabulate(found_differences, headers=REGDIFF_HEADERS,
                             tablefmt='fancy_grid'))
    click.secho(f'Detected {len(found_differences)} differences', fg='green')


@click.command()
@click.argument('hive_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True)
@click.option('-p', 'primary_log_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True), required=True)
@click.option('-s', 'secondary_log_path', type=click.Path(exists=True, dir_okay=False, resolve_path=True),
              required=False)
@click.option('-o', 'output_path', type=click.Path(exists=False, dir_okay=False, resolve_path=True), required=False)
@click.option('-v', '--verbose', is_flag=True, default=True, help='Verbosity')
def parse_transaction_log(hive_path, primary_log_path, secondary_log_path, output_path, verbose):
    _setup_logging(verbose=verbose)
    logger.info(f'Processing hive {hive_path} with transaction log {primary_log_path}')
    if secondary_log_path:
        logger.info(f'Processing hive {hive_path} with secondary transaction log {primary_log_path}')

    restored_hive_path, recovered_dirty_pages_count = apply_transaction_logs(hive_path, primary_log_path,
                                                                             secondary_log_path=secondary_log_path,
                                                                             restored_hive_path=output_path,
                                                                             verbose=verbose)
    if recovered_dirty_pages_count:
        click.secho(
            f'Recovered {recovered_dirty_pages_count} dirty pages. Restored hive is at {restored_hive_path}',
            fg='green')
