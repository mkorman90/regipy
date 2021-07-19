import os
from io import BytesIO

import logging

from construct import Int32ul

from regipy import boomerang_stream
from regipy.exceptions import RegistryRecoveryException
from regipy.hive_types import HVLE_TRANSACTION_LOG_MAGIC, DIRT_TRANSACTION_LOG_MAGIC
from regipy.registry import RegistryHive
from regipy.structs import TRANSACTION_LOG, REGF_HEADER_SIZE, REGF_HEADER, HBIN_HEADER

logger = logging.getLogger(__name__)


def _parse_hvle_block(hive_path, transaction_log_stream, log_size, expected_sequence_number):
    """

    :param hive_path:
    :param transaction_log_stream:
    :param log_size:
    :param expected_sequence_number:
    :return:
    """
    recovered_dirty_pages_count = 0
    restored_hive_buffer = BytesIO(open(hive_path, 'rb').read())

    hvle_block_start_offset = transaction_log_stream.tell()

    while hvle_block_start_offset < log_size:
        logger.info(f'Parsing hvle block at {hex(hvle_block_start_offset)}')
        with boomerang_stream(transaction_log_stream) as x:
            if x.read(4) != b'HvLE':
                logger.info('Reached a non HvLE object. stopping')
                break

        logger.info(f'Parsing HvLE block at {hex(hvle_block_start_offset)}')
        parsed_hvle_block = TRANSACTION_LOG.parse_stream(transaction_log_stream)
        logger.info(f'Currently at start of dirty pages: {transaction_log_stream.tell()}')
        logger.info(f'seq number: {parsed_hvle_block.sequence_number}')
        logger.info(f'dirty pages: {parsed_hvle_block.dirty_pages_count}')

        if parsed_hvle_block.sequence_number == expected_sequence_number:
            logger.info(f'This hvle block holds valid dirty blocks')
            expected_sequence_number += 1

        for dirty_page_entry in parsed_hvle_block.dirty_pages_references:
            # Write the actual dirty page to the original hive
            target_offset = REGF_HEADER_SIZE + dirty_page_entry.offset
            restored_hive_buffer.seek(target_offset)
            transaction_log_stream_offset = transaction_log_stream.tell()
            dirty_page_buffer = transaction_log_stream.read(dirty_page_entry.size)
            restored_hive_buffer.write(dirty_page_buffer)
            logger.info(f'Restored {dirty_page_entry.size} bytes to offset {hex(target_offset)} '
                        f'from offset {hex(transaction_log_stream_offset)}')
            recovered_dirty_pages_count += 1

        # TODO: update hive flags from hvle to original header

        # Update sequence numbers are at offsets 4 & 8:
        restored_hive_buffer.seek(4)
        restored_hive_buffer.write(Int32ul.build(expected_sequence_number))
        restored_hive_buffer.write(Int32ul.build(expected_sequence_number))

        # Update hbins size from hvle to original header at offset 40
        restored_hive_buffer.seek(40)
        restored_hive_buffer.write(Int32ul.build(parsed_hvle_block.hive_bin_size))

        transaction_log_stream.seek(hvle_block_start_offset + parsed_hvle_block.log_size)
        hvle_block_start_offset = hvle_block_start_offset + parsed_hvle_block.log_size

    return restored_hive_buffer, recovered_dirty_pages_count


def _parse_dirt_block(hive_path, transaction_log, hbins_data_size):
    restored_hive_buffer = BytesIO(open(hive_path, 'rb').read())
    recovered_dirty_pages_count = 0

    dirty_vector_length = hbins_data_size // 4096

    if transaction_log.read(4) != b'DIRT':
        raise RegistryRecoveryException('Expected DIRT signature!')

    log_file_base = 1024  # 512 + len(b'DIRT') + dirty_vector_length
    primary_file_base = 4096
    bitmap = transaction_log.read(dirty_vector_length)

    bit_counter = 0
    bitmap_offset = 0

    # Tuples of offset in primary and offset in transaction log
    offsets = []
    while bit_counter < dirty_vector_length * 8:
        is_bit_set = ((bitmap[bit_counter // 8] >> (bit_counter % 8)) & 1) != 0
        if is_bit_set:
            # We skip the basic block for the offsets
            registry_offset = primary_file_base + (bit_counter * 512)

            # And also the DIRT signature in the transaction log
            transaction_log_offset = log_file_base + (bitmap_offset * 512)

            offsets.append((registry_offset, transaction_log_offset))
            bitmap_offset += 1

        bit_counter += 1

    for registry_offset, transaction_log_offset in offsets:
        logger.debug(f'Reading 512 bytes from {transaction_log_offset} writing to {registry_offset}')

        restored_hive_buffer.seek(registry_offset)
        transaction_log.seek(transaction_log_offset)

        restored_hive_buffer.write(transaction_log.read(512))

        recovered_dirty_pages_count += 1
    return restored_hive_buffer, recovered_dirty_pages_count


def _parse_transaction_log(registry_hive, hive_path, transaction_log_path):
    log_size = os.path.getsize(transaction_log_path)
    logger.info(f'Log Size: {log_size}')

    expected_sequence_number = registry_hive.header.secondary_sequence_num

    with open(transaction_log_path, 'rb') as transaction_log:
        # Skip the REGF header
        transaction_log.seek(512, 0)

        # Read the header of the transaction log vector and determine its type
        with boomerang_stream(transaction_log) as s:
            magic = s.read(4)

        if magic == HVLE_TRANSACTION_LOG_MAGIC:
            # This is an HvLE block
            restored_hive_buffer, recovered_dirty_pages_count = _parse_hvle_block(hive_path, transaction_log, log_size,
                                                                                  expected_sequence_number)
        elif magic == DIRT_TRANSACTION_LOG_MAGIC:
            # This is an old transaction log - DIRT
            hbins_data_size = registry_hive.header.hive_bins_data_size
            restored_hive_buffer, recovered_dirty_pages_count = _parse_dirt_block(hive_path, transaction_log,
                                                                                  hbins_data_size)
        else:
            raise RegistryRecoveryException(f'The transaction log vector magic was not expected: {magic}')
    return restored_hive_buffer, recovered_dirty_pages_count


def apply_transaction_logs(hive_path, primary_log_path, secondary_log_path=None,
                           restored_hive_path=None, verbose=False):
    """
    Apply transactions logs
    :param hive_path: The path to the original hive
    :param primary_log_path: The path to the primary log path
    :param secondary_log_path: The path to the secondary log path (optional).
    :param restored_hive_path: Path to save the restored hive
    :param verbose: verbosity
    :return:
    """
    recovered_dirty_pages_total_count = 0

    if not restored_hive_path:
        restored_hive_path = f'{hive_path}.restored'

    registry_hive = RegistryHive(hive_path)

    if secondary_log_path:
        registry_hive = RegistryHive(hive_path)
        restored_hive_buffer, recovered_dirty_pages_count = _parse_transaction_log(registry_hive, hive_path,
                                                                                   secondary_log_path)
        # Write to disk the modified registry hive
        with open(restored_hive_path, 'wb') as f:
            restored_hive_buffer.seek(0)
            f.write(restored_hive_buffer.read())

        recovered_dirty_pages_total_count += recovered_dirty_pages_count
        logger.info(f'Recovered {recovered_dirty_pages_count} pages from secondary transaction log')

    # Parse the primary transaction log
    log_size = os.path.getsize(primary_log_path)
    logger.info(f'Log Size: {log_size}')

    # If no secondary transaction log was give, apply the first transaction log on the original hive
    target_hive = restored_hive_path if secondary_log_path else hive_path
    restored_hive_buffer, recovered_dirty_pages_count = _parse_transaction_log(registry_hive, target_hive,
                                                                               primary_log_path)
    logger.info(f'Recovered {recovered_dirty_pages_count} pages from primary transaction log')

    recovered_dirty_pages_total_count += recovered_dirty_pages_count

    # Write to disk the modified registry hive
    with open(restored_hive_path, 'wb') as f:
        restored_hive_buffer.seek(0)
        f.write(restored_hive_buffer.read())

    return restored_hive_path, recovered_dirty_pages_total_count
