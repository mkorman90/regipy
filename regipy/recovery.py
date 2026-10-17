import logging
import os
import struct
from io import BytesIO

from construct import ConstructError, Int32ul

from regipy import boomerang_stream
from regipy.exceptions import RegistryRecoveryException
from regipy.hive_types import DIRT_TRANSACTION_LOG_MAGIC, HVLE_TRANSACTION_LOG_MAGIC
from regipy.registry import RegistryHive
from regipy.structs import HVLE_BLOCK_HEADER_SIZE, REGF_HEADER_SIZE, TRANSACTION_LOG

logger = logging.getLogger(__name__)

# Marvin32 seed used by the Windows registry for the HvLE transaction-log
# entry hashes (Hash-1 / Hash-2), per the registry file format specification.
MARVIN32_SEED = 0x82EF4D887A4E55C5

# A hive can grow at most to its 32-bit addressable size.
MAX_HIVE_SIZE = 0x7FFFFFFF


def _marvin32(buffer):
    """Marvin32 hash of *buffer* (the 64-bit result as an int), seeded as the
    registry seeds its log entry hashes.

    Per the Windows registry file format specification (mrsuhanov/regf,
    "Windows registry file format specification", transaction log section,
    notes 1-3), the Hash-1 and Hash-2 fields of an HvLE log entry are
    Marvin32 hashes seeded with 82 EF 4D 88 7A 4E 55 C5; this is a port of the
    Marvin32 implementation in the specification author's yarp parser
    (yarp/RegistryFile.py).
    """
    lo = MARVIN32_SEED & 0xFFFFFFFF
    hi = (MARVIN32_SEED >> 32) & 0xFFFFFFFF

    def rotl(value, shift):
        return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

    def mix(value):
        nonlocal lo, hi
        lo = (lo + value) & 0xFFFFFFFF
        hi ^= lo
        lo = (rotl(lo, 20) + hi) & 0xFFFFFFFF
        hi = (rotl(hi, 9) ^ lo) & 0xFFFFFFFF
        lo = (rotl(lo, 27) + hi) & 0xFFFFFFFF
        hi = rotl(hi, 19)

    position = 0
    remaining = len(buffer)
    while remaining >= 4:
        mix(struct.unpack_from("<I", buffer, position)[0])
        position += 4
        remaining -= 4

    # Hash the remaining 0-3 bytes, left-padded with 0x80
    final = 0x80
    if remaining == 3:
        final |= buffer[position + 2] << 8
    elif remaining == 2:
        final |= buffer[position + 1] << 8
    elif remaining == 1:
        final |= buffer[position]
    mix(final)
    mix(0)
    return (hi << 32) | lo


def _scan_hvle_entries(log_path):
    """Parse and validate every HvLE entry of the transaction log at *log_path*.

    Returns a list of (sequence_number, hive_bin_size, pages) tuples, where
    pages is a list of (offset, data) tuples (offset relative to the REGF
    header, data being the page image).

    Scanning stops at the first invalid entry: per the registry file format
    specification, recovery stops and only the preceding log entries are
    applied if an entry's Hash-1/Hash-2 fields do not verify, or if its Hive
    bins data size field is not a multiple of 4096 bytes. A log whose first
    entry has a log_size smaller than the 40-byte block header is rejected
    outright (RegistryRecoveryException), since it cannot be parsed at all.
    """
    with open(log_path, "rb") as log_file:
        log_data = log_file.read()

    entries = []
    offset = 512  # skip the REGF header
    while offset + HVLE_BLOCK_HEADER_SIZE <= len(log_data):
        if log_data[offset : offset + 4] != HVLE_TRANSACTION_LOG_MAGIC:
            logger.info("Reached a non HvLE object. stopping")
            break

        (log_size,) = struct.unpack_from("<I", log_data, offset + 4)

        # The only thing that advances this loop is the block's own log_size field.
        # A corrupt or crafted log with log_size < HVLE_BLOCK_HEADER_SIZE (the size of the
        # block header itself) would otherwise be re-parsed forever at the same offset.
        if log_size < HVLE_BLOCK_HEADER_SIZE:
            raise RegistryRecoveryException(
                f"HvLE block at {hex(offset)} has an invalid log_size "
                f"({log_size}) - smaller than the {HVLE_BLOCK_HEADER_SIZE}-byte block header. "
                f"The transaction log is corrupt or malformed, refusing to continue."
            )

        entry_end = offset + log_size
        if entry_end > len(log_data):
            logger.warning(f"HvLE entry at {hex(offset)} extends beyond the end of the log. Stopping.")
            break

        # The entry's fixed header and page references are the TRANSACTION_LOG
        # struct (regipy/structs.py); parsing it against the entry's own byte
        # range also validates that the references table fits inside it.
        try:
            parsed_entry = TRANSACTION_LOG.parse(log_data[offset:entry_end])
        except ConstructError:
            logger.warning(f"HvLE entry at {hex(offset)} could not be parsed. Stopping recovery.")
            break

        sequence_number = parsed_entry.sequence_number
        hive_bin_size = parsed_entry.hive_bin_size

        # Hash-1 covers everything from the first page reference on (Size - 40 bytes);
        # Hash-2 covers the first 32 bytes of the entry (including the stored Hash-1).
        # An entry that fails either check is corrupt (or was truncated by a crash) and
        # everything after it is suspect: recovery stops here.
        if (
            _marvin32(log_data[offset + HVLE_BLOCK_HEADER_SIZE : entry_end]) != parsed_entry.hash_1
            or _marvin32(log_data[offset : offset + 32]) != parsed_entry.hash_2
        ):
            logger.warning(
                f"HvLE entry with sequence number {sequence_number} at {hex(offset)} failed hash verification. "
                "Stopping recovery; only the preceding entries are applied."
            )
            break

        # Hive bins data size that is not a multiple of 4096 bytes marks the
        # entry as invalid; recovery stops and only preceding entries apply.
        if hive_bin_size % 4096 != 0:
            logger.warning(
                f"HvLE entry with sequence number {sequence_number} at {hex(offset)} declares a hive bins data "
                f"size of {hex(hive_bin_size)} that is not a multiple of 4096 bytes. Stopping recovery; "
                "only the preceding entries are applied."
            )
            break

        references = [(reference.offset, reference.size) for reference in parsed_entry.dirty_pages_references]
        page_start = offset + HVLE_BLOCK_HEADER_SIZE + 8 * len(references)

        # Validate the page data bounds before trusting the references: a
        # hash-valid entry could otherwise declare more page data than it holds.
        if page_start + sum(page_size for _, page_size in references) > entry_end:
            logger.warning(
                f"HvLE entry with sequence number {sequence_number} at {hex(offset)} declares more page "
                "data than the entry holds. Stopping recovery."
            )
            break

        pages = []
        position = page_start
        for page_offset, page_size in references:
            pages.append((page_offset, log_data[position : position + page_size]))
            position += page_size

        logger.info(f"HvLE entry at {hex(offset)}: seq {sequence_number}, {len(references)} dirty pages")
        entries.append((sequence_number, hive_bin_size, pages))
        offset = entry_end

    return entries


def _apply_entries_to_buffer(entries, restored_hive_buffer, hive_file_size, hive_secondary_sequence_num):
    """Apply a validated, ordered list of HvLE entries (already ordered with the
    earlier sequence chain first) to the hive in *restored_hive_buffer*.

    Sequence continuity is enforced across the whole list: per the registry
    file format specification, recovery stops after entry N if entry N + 1
    does not follow (e.g. because of a gap between the two transaction log
    files), so stale pages from a reused log cannot clobber newer pages.

    The hive may grow to the bin size an entry declares (per the spec, the
    primary file is grown according to the entry's Hive bins data size), but
    the growth is bounded: the new size must be a multiple of 4096, within
    the 32-bit addressable range, and no larger than the current hive plus
    the log's own footprint - a tiny log cannot claim a multi-gigabyte hive.

    :param entries: list of (sequence_number, hive_bin_size, pages, log_file_size) tuples
    :param restored_hive_buffer: BytesIO holding the hive being restored
    :param hive_file_size: original size of the hive
    :param hive_secondary_sequence_num: the hive's secondary sequence number,
        for reporting gaps between the hive and the first applied entry
    :return: (recovered_dirty_pages_count, last_applied_sequence, last_applied_bin_size)
    """
    recovered_dirty_pages_count = 0
    expected_sequence = None
    last_applied_sequence = None
    last_applied_bin_size = None

    for sequence_number, hive_bin_size, pages, log_file_size in entries:
        if expected_sequence is not None and sequence_number != expected_sequence:
            logger.warning(
                f"Log entry with sequence number {sequence_number} does not continue the recovered sequence "
                f"(expected {expected_sequence}). Stopping recovery; only the preceding entries are applied."
            )
            break

        if last_applied_sequence is None and sequence_number != hive_secondary_sequence_num:
            if sequence_number > hive_secondary_sequence_num:
                logger.warning(
                    f"The first applied log entry has sequence number {sequence_number} but the hive's secondary "
                    f"sequence number is {hive_secondary_sequence_num}; log entries {hive_secondary_sequence_num}-"
                    f"{sequence_number - 1} are missing from the log."
                )
            else:
                logger.warning(
                    f"The first applied log entry has sequence number {sequence_number}, which is below the hive's "
                    f"secondary sequence number {hive_secondary_sequence_num}; the log is stale relative to the hive."
                )

        for page_offset, page_data in pages:
            target_offset = REGF_HEADER_SIZE + page_offset

            # Dirty page offsets come from the log (u32) and may be corrupt.
            # Without this check a crafted log would make restored_hive_buffer balloon
            # up to 4 GiB (and be written to disk as such). The hive may grow to the
            # bin size the entry declares, bounded as documented above.
            if target_offset + len(page_data) > restored_hive_buffer.getbuffer().nbytes:
                if (
                    hive_bin_size % 4096 == 0
                    and target_offset + len(page_data) <= hive_bin_size
                    and hive_bin_size <= MAX_HIVE_SIZE
                    and hive_bin_size <= restored_hive_buffer.getbuffer().nbytes + log_file_size
                ):
                    logger.info(f"Hive grows from {hex(hive_file_size)} to {hex(hive_bin_size)} bytes")
                    restored_hive_buffer.write(b"\x00" * (hive_bin_size - restored_hive_buffer.getbuffer().nbytes))
                if target_offset + len(page_data) > restored_hive_buffer.getbuffer().nbytes:
                    raise RegistryRecoveryException(
                        f"Dirty page entry at offset {hex(page_offset)} points outside "
                        f"of the hive (size {hex(restored_hive_buffer.getbuffer().nbytes)}). The transaction log "
                        f"is corrupt or malformed, refusing to continue."
                    )

            restored_hive_buffer.seek(target_offset)
            restored_hive_buffer.write(page_data)
            logger.info(f"Restored {len(page_data)} bytes to offset {hex(target_offset)}")
            recovered_dirty_pages_count += 1

        expected_sequence = sequence_number + 1
        last_applied_sequence = sequence_number
        last_applied_bin_size = hive_bin_size

    return recovered_dirty_pages_count, last_applied_sequence, last_applied_bin_size


def _apply_header_state(restored_hive_buffer, last_applied_sequence, last_applied_bin_size):
    """Write the header state resulting from the applied log entries: the
    base block's primary sequence number becomes the last applied entry's
    sequence number (and the secondary one the preceding number), and the
    Hive bins data size becomes the last applied entry's declared size."""
    if last_applied_sequence is None:
        return

    # Sequence numbers are at offsets 4 & 8:
    restored_hive_buffer.seek(4)
    restored_hive_buffer.write(Int32ul.build(last_applied_sequence))
    restored_hive_buffer.write(Int32ul.build(last_applied_sequence - 1))

    # Update hbins size from hvle to original header at offset 40
    restored_hive_buffer.seek(40)
    restored_hive_buffer.write(Int32ul.build(last_applied_bin_size))


def _order_and_chain(entries_by_path, hive_secondary_sequence_num):
    """Order the parsed logs so the earlier sequence chain is applied first,
    and enforce that the second log continues exactly where the first ends
    (first entry of the next log == N + 1). Returns the ordered, flattened
    entry list; a second log that does not continue the sequence is dropped
    (recovery stops, only the first log applies)."""
    logs = [entry for entry in entries_by_path if entry]

    if not logs:
        return []

    if len(logs) == 1:
        return logs[0]

    first, second = sorted(logs, key=lambda entries: entries[0][0])
    if second[0][0] != first[-1][0] + 1:
        logger.warning(
            f"The first entry of the second log (sequence {second[0][0]}) does not continue the first log "
            f"(last sequence {first[-1][0]}). Stopping recovery after the first log."
        )
        return first
    return first + second


def _parse_dirt_block(hive_path, transaction_log, hbins_data_size):
    restored_hive_buffer = BytesIO(open(hive_path, "rb").read())
    recovered_dirty_pages_count = 0

    dirty_vector_length = hbins_data_size // 4096

    if transaction_log.read(4) != b"DIRT":
        raise RegistryRecoveryException("Expected DIRT signature!")

    log_file_base = 1024  # 512 + len(b'DIRT') + dirty_vector_length
    primary_file_base = 4096
    bitmap = transaction_log.read(dirty_vector_length)
    if len(bitmap) < dirty_vector_length:
        raise RegistryRecoveryException(
            f"Expected a dirty page vector of {dirty_vector_length} bytes (based on the hive's "
            f"hbins_data_size) but the transaction log only holds {len(bitmap)} bytes. "
            f"The transaction log is corrupt or does not match the hive, refusing to continue."
        )

    hive_file_size = restored_hive_buffer.getbuffer().nbytes

    bit_counter = 0
    bitmap_offset = 0

    # Tuples of offset in primary and offset in transaction log
    offsets = []
    while bit_counter < dirty_vector_length * 8:
        is_bit_set = ((bitmap[bit_counter // 8] >> (bit_counter % 8)) & 1) != 0
        if is_bit_set:
            # We skip the basic block for the offsets
            registry_offset = primary_file_base + (bit_counter * 512)

            # hbins_data_size comes from the hive header (u32) and may be corrupt -
            # without this check a crafted hive would make restored_hive_buffer balloon.
            if registry_offset >= hive_file_size:
                raise RegistryRecoveryException(
                    f"Dirty page at offset {hex(registry_offset)} points outside of the hive "
                    f"(size {hive_file_size}). The hive header or transaction log is corrupt, "
                    f"refusing to continue."
                )

            # And also the DIRT signature in the transaction log
            transaction_log_offset = log_file_base + (bitmap_offset * 512)

            offsets.append((registry_offset, transaction_log_offset))
            bitmap_offset += 1

        bit_counter += 1

    for registry_offset, transaction_log_offset in offsets:
        logger.debug(f"Reading 512 bytes from {transaction_log_offset} writing to {registry_offset}")

        restored_hive_buffer.seek(registry_offset)
        transaction_log.seek(transaction_log_offset)

        restored_hive_buffer.write(transaction_log.read(512))

        recovered_dirty_pages_count += 1
    return restored_hive_buffer, recovered_dirty_pages_count


def _detect_log_magic(transaction_log_path):
    with open(transaction_log_path, "rb") as transaction_log:
        transaction_log.seek(512, 0)
        return transaction_log.read(4)


def _parse_transaction_log_legacy(registry_hive, hive_path, transaction_log_path):
    """Apply a single transaction log to the hive at *hive_path* (the legacy
    per-file path, used when a DIRT-format log is involved).

    :return: (restored_hive_buffer, recovered_dirty_pages_count)
    """
    log_size = os.path.getsize(transaction_log_path)
    logger.info(f"Log Size: {log_size}")

    with open(transaction_log_path, "rb") as transaction_log:
        # Skip the REGF header
        transaction_log.seek(512, 0)

        # Read the header of the transaction log vector and determine its type
        with boomerang_stream(transaction_log) as s:
            magic = s.read(4)

        if magic == DIRT_TRANSACTION_LOG_MAGIC:
            # This is an old transaction log - DIRT
            hbins_data_size = registry_hive.header.hive_bins_data_size
            restored_hive_buffer, recovered_dirty_pages_count = _parse_dirt_block(hive_path, transaction_log, hbins_data_size)
        else:
            if magic != HVLE_TRANSACTION_LOG_MAGIC:
                raise RegistryRecoveryException(f"The transaction log vector magic was not expected: {magic}")
            entries = _scan_hvle_entries(transaction_log_path)
            entries = [(sequence, bin_size, pages, log_size) for sequence, bin_size, pages in entries]
            restored_hive_buffer = BytesIO(open(hive_path, "rb").read())
            hive_file_size = restored_hive_buffer.getbuffer().nbytes
            recovered_dirty_pages_count, last_sequence, last_bin_size = _apply_entries_to_buffer(
                entries, restored_hive_buffer, hive_file_size, registry_hive.header.secondary_sequence_num
            )
            _apply_header_state(restored_hive_buffer, last_sequence, last_bin_size)
    return restored_hive_buffer, recovered_dirty_pages_count


def apply_transaction_logs(
    hive_path,
    primary_log_path,
    secondary_log_path=None,
    restored_hive_path=None,
    verbose=False,
):
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
        restored_hive_path = f"{hive_path}.restored"

    registry_hive = RegistryHive(hive_path)

    # Legacy path: a DIRT-format log (or a DIRT/HvLE mix) is applied with the
    # historical per-file semantics. HvLE/HvLE pairs are ordered by content
    # below, since which file holds the earlier sequence chain is a property
    # of the logs themselves, not of the caller's argument order.
    log_magics = {primary_log_path: _detect_log_magic(primary_log_path)}
    if secondary_log_path:
        log_magics[secondary_log_path] = _detect_log_magic(secondary_log_path)

    if any(magic != HVLE_TRANSACTION_LOG_MAGIC for magic in log_magics.values()):
        if secondary_log_path:
            restored_hive_buffer, recovered_dirty_pages_count = _parse_transaction_log_legacy(
                registry_hive, hive_path, secondary_log_path
            )
            # Write to disk the modified registry hive
            with open(restored_hive_path, "wb") as f:
                restored_hive_buffer.seek(0)
                f.write(restored_hive_buffer.read())

            recovered_dirty_pages_total_count += recovered_dirty_pages_count
            logger.info(f"Recovered {recovered_dirty_pages_count} pages from secondary transaction log")

        target_hive = restored_hive_path if secondary_log_path else hive_path
        restored_hive_buffer, recovered_dirty_pages_count = _parse_transaction_log_legacy(
            registry_hive, target_hive, primary_log_path
        )
        logger.info(f"Recovered {recovered_dirty_pages_count} pages from primary transaction log")

        recovered_dirty_pages_total_count += recovered_dirty_pages_count

        # Write to disk the modified registry hive
        with open(restored_hive_path, "wb") as f:
            restored_hive_buffer.seek(0)
            f.write(restored_hive_buffer.read())

        return restored_hive_path, recovered_dirty_pages_total_count

    # HvLE path: parse and validate both logs, apply the earlier sequence
    # chain first, and enforce sequence continuity across them.
    entries_by_log = []
    for log_path in [primary_log_path, secondary_log_path]:
        if not log_path:
            continue
        log_size = os.path.getsize(log_path)
        logger.info(f"Log Size: {log_size}")
        entries = _scan_hvle_entries(log_path)
        entries = [(sequence, bin_size, pages, log_size) for sequence, bin_size, pages in entries]
        entries_by_log.append(entries)

    ordered_entries = _order_and_chain(entries_by_log, registry_hive.header.secondary_sequence_num)

    restored_hive_buffer = BytesIO(open(hive_path, "rb").read())
    hive_file_size = restored_hive_buffer.getbuffer().nbytes
    recovered_dirty_pages_total_count, last_sequence, last_bin_size = _apply_entries_to_buffer(
        ordered_entries, restored_hive_buffer, hive_file_size, registry_hive.header.secondary_sequence_num
    )
    _apply_header_state(restored_hive_buffer, last_sequence, last_bin_size)
    logger.info(f"Recovered {recovered_dirty_pages_total_count} pages from the transaction logs")

    # Write to disk the modified registry hive
    with open(restored_hive_path, "wb") as f:
        restored_hive_buffer.seek(0)
        f.write(restored_hive_buffer.read())

    return restored_hive_path, recovered_dirty_pages_total_count
