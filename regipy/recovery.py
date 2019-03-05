import os
from io import BytesIO

import logbook

from construct import Int32ul

from regipy.registry import RegistryHive
from regipy.structs import TRANSACTION_LOG, REGF_HEADER_SIZE

logger = logbook.Logger(__name__)


def apply_transaction_logs(hive_path, transaction_log_path, restored_hive_path=None, verbose=False):
    restored_hive_buffer = BytesIO(open(hive_path, 'rb').read())

    if not restored_hive_path:
        restored_hive_path = f'{hive_path}.restored'

    registry_hive = RegistryHive(hive_path)
    log_size = os.path.getsize(transaction_log_path)
    expected_sequence_number = registry_hive.header.secondary_sequence_num

    logger.info(f'Log Size: {log_size}')

    recovered_dirty_pages_count = 0
    with open(transaction_log_path, 'rb') as transaction_log:
        # Skip REGF header
        transaction_log.seek(512)
        hvle_block_start_offset = transaction_log.tell()

        while hvle_block_start_offset < log_size:
            logger.info(f'Parsing hvle block at {hvle_block_start_offset}')

            parsed_hvle_block = TRANSACTION_LOG.parse_stream(transaction_log)
            logger.info(f'Currently at start of dirty pages: {transaction_log.tell()}')
            logger.info(f'seq number: {parsed_hvle_block.sequence_number}')
            logger.info(f'dirty pages: {parsed_hvle_block.dirty_pages_count}')

            if parsed_hvle_block.sequence_number == expected_sequence_number:
                logger.info(f'This hvle block holds valid dirty blocks')
                expected_sequence_number += 1
            else:
                logger.info(f'This block is invalid. stopping.')
                break

            for dirty_page_entry in parsed_hvle_block.dirty_pages_references:
                # Write the actual dirty page to the original hive
                target_offset = REGF_HEADER_SIZE + dirty_page_entry.offset
                restored_hive_buffer.seek(target_offset)
                dirty_page_buffer = transaction_log.read(dirty_page_entry.size)
                restored_hive_buffer.write(dirty_page_buffer)
                logger.info(f'Restored {dirty_page_entry.size} bytes to offset {target_offset}')
                recovered_dirty_pages_count += 1

            # TODO: update hive flags from hvle to original header

            # Update sequence numbers are at offsets 4 & 8:
            restored_hive_buffer.seek(4)
            restored_hive_buffer.write(Int32ul.build(expected_sequence_number))
            restored_hive_buffer.write(Int32ul.build(expected_sequence_number))

            # Update hbins size from hvle to original header at offset 40
            restored_hive_buffer.seek(40)
            restored_hive_buffer.write(Int32ul.build(parsed_hvle_block.hive_bin_size))

            transaction_log.seek(hvle_block_start_offset + parsed_hvle_block.log_size)
            hvle_block_start_offset = hvle_block_start_offset + parsed_hvle_block.log_size

    # Write to disk the modified registry hive
    with open(restored_hive_path, 'wb') as f:
        restored_hive_buffer.seek(0)
        f.write(restored_hive_buffer.read())

    return restored_hive_path, recovered_dirty_pages_count
