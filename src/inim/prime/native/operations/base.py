import struct
from typing import Final

from inim.prime.native.const import AddressTable, Encoding, CommandOperation
from inim.prime.native.wire.protocol import Protocol


async def resolve_address(protocol: Protocol, index: int) -> int:
    """
    Resolves an address by performing an indirection lookup.

    The provided index is used to retrieve a 32-bit value from an
    address mapping table. That value represents the resolved address.

    :param protocol: Protocol object to perform the request.
    :param index: Index into the address table (not the final address).
    :return: Resolved 32-bit address stored at the given table entry.
    """
    response = await protocol.read_memory(index, AddressTable.ENTRY_SIZE)
    return struct.unpack(Encoding.UINT32_LE, response)[0]


async def get_panel_info(
        protocol: Protocol,
) -> tuple[str, str, str]:
    RESPONSE_PAYLOAD_LENGTH: Final[int] = 38
    SERIAL_NUMBER: Final[slice] = slice(0, 16)
    DESCRIPTION: Final[slice] = slice(16, 32)

    panel_info = await protocol.execute_command(
        operation = CommandOperation.GET_PANEL_INFO,
        response_payload_length = RESPONSE_PAYLOAD_LENGTH,
    )

    serial_number = panel_info[SERIAL_NUMBER].decode("ascii").rstrip()
    description = panel_info[DESCRIPTION].decode("ascii").rstrip()
    firmware, model = description.split(" ", maxsplit = 1)

    return serial_number, firmware, model
