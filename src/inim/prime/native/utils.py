from __future__ import annotations

from inim.prime.native.const import CRC16_TABLE


def slice_size(s: slice) -> int:
    return s.stop - s.start


def round_up_to_block(
        n: int,
        block: int,
) -> int:
    """
    Rounds up a number to the nearest multiple of the specified block that is greater or equal than it.
    :param n:       The number to round up.
    :param block:   Value of the multiplier used to round up the number.
    :return:        The rounded up number.
    """
    return ((n + block - 1) // block) * block


def crc16_arc(
        data: bytes | bytearray,
) -> int:
    """
    Computes CRC-16/ARC checksum over data.
    :param data:   The data to compute CRC-16/ARC checksum over.
    :return:       The computed CRC-16/ARC checksum as a 16-bit integer (0–65535).
    """
    # Zero-initialised CRC value
    crc = 0

    for byte in data:
        # XOR the incoming byte with the low 8 bits of the running CRC
        # to produce a table index in range 0–255
        table_index = (crc ^ byte) & 0xFF

        # Retrieves the precomputed CRC value using the obtained table_index.
        table_value = CRC16_TABLE[table_index]

        # Takes the 8 most significant bits of CRC (the high byte)
        high_byte = (crc >> 8) & 0xFF

        # XOR the CRC high_byte with table_value
        crc = high_byte ^ table_value

    return crc & 0xFFFF
