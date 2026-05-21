from typing import Final

from inim.prime.native.const import AddressTable, Encoding, CommandOperation
from inim.prime.native.utils import decode_int
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
    return decode_int(response, Encoding.UINT32_LE)
