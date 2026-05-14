import asyncio
import struct
from typing import Final

from prime.protocol.const import AddressTable, Panel, Encoding, CommandOperation
from prime.protocol.models import PartitionMode, PartitionStatus
from prime.protocol.models.partitions import Partition
from prime.protocol.wire.protocol import Protocol
from . import resolve_address

PARTITION_MODE_MAP = {
    0x01: PartitionMode.TOTAL,
    0x02: PartitionMode.PARTIAL,
    0x03: PartitionMode.INSTANT,
    0x04: PartitionMode.DISARMED,
}

PARTITION_MODE_REVERSE_MAP = {
    value: key for key, value in PARTITION_MODE_MAP.items()
}


async def set_partition_modes(
        protocol: Protocol,
        partition_modes: dict[int, PartitionMode],
        pin: str | Panel.DefaultMasterPin = Panel.DEFAULT_MASTER_PIN,
) -> None:
    command_data = bytearray(Panel.MAX_PARTITION_NUMBER)

    for idx, partition_mode in partition_modes.items():
        if idx < 1 or idx > Panel.MAX_PARTITION_NUMBER:
            raise IndexError(f'Partition mode {idx} out of range')

        command_data[idx - 1] = PARTITION_MODE_REVERSE_MAP[partition_mode]

    await protocol.execute_command(
        operation = CommandOperation.SET_PARTITION_MODES,
        data = command_data,
        pin = pin,
    )


async def reset_partitions(
        protocol: Protocol,
        partition_ids: set[int],
        pin: str | Panel.DefaultMasterPin = Panel.DEFAULT_MASTER_PIN,
) -> None:
    partitions_to_reset_int = 0
    for idx in partition_ids:
        if idx < 1 or idx > Panel.MAX_PARTITION_NUMBER:
            raise IndexError(f'Partition id {idx} out of range')
        partitions_to_reset_int += 2 ** (idx - 1)

    command_data = struct.pack(Encoding.UINT32_LE, partitions_to_reset_int)

    await protocol.execute_command(
        operation = CommandOperation.RESET_PARTITIONS,
        data = command_data,
        pin = pin,
    )


async def get_partition_statuses(
        protocol: Protocol,
        pin: str | Panel.DefaultMasterPin = Panel.DEFAULT_MASTER_PIN,
) -> dict[int, PartitionStatus]:
    ### Constants
    HEADER_SIZE: Final[int] = 18
    PARTITION_SIZE: Final[int] = 3
    TOTAL_SIZE: Final[int] = HEADER_SIZE + PARTITION_SIZE * Panel.MAX_PARTITION_NUMBER  # 108

    CONFIGURED_MASK: Final[int] = 0x10
    ALARM_MASK: Final[int] = 0x01

    ### Decode single partition bytes
    def decode_partition_status(p: bytes) -> PartitionStatus | None:

        ### Byte 1
        mode = PARTITION_MODE_MAP.get(p[1])

        if mode is None:
            return None

        ### Byte 2
        # is_configured = bool(p[2] & CONFIGURED_MASK)
        has_alarm = bool(p[2] & ALARM_MASK)

        return PartitionStatus(
            partition_mode = mode,
            alarm = has_alarm,
            alarm_memory = has_alarm,
        )

    ### Main function
    response = await protocol.execute_command(
        operation = CommandOperation.GET_PARTITION_STATUSES,
        pin = pin,
        response_payload_length = TOTAL_SIZE,
    )

    partitions: dict[int, PartitionStatus] = {}

    for idx, offset in enumerate(
            range(HEADER_SIZE, TOTAL_SIZE, PARTITION_SIZE),
            start = 1,
    ):
        chunk = response[offset:offset + PARTITION_SIZE]
        partition = decode_partition_status(chunk)
        if partition is not None:
            partitions[idx] = partition

    return partitions


async def get_partition_names(protocol: Protocol) -> dict[int, str]:
    NAME_SIZE: Final[int] = 16

    address = await resolve_address(protocol, AddressTable.GET_PARTITION_NAMES)
    response = await protocol.read_memory(address, Panel.MAX_PARTITION_NUMBER * NAME_SIZE)

    partition_names: dict[int, str] = {}

    for index in range(Panel.MAX_PARTITION_NUMBER):
        partition_name_bytes = response[index * NAME_SIZE:(index + 1) * NAME_SIZE]

        if partition_name_bytes != bytes(NAME_SIZE):
            partition_name = partition_name_bytes.decode("ascii").rstrip()
            partition_names[index + 1] = partition_name

    return partition_names


async def get_partitions(protocol: Protocol) -> list[Partition]:
    partitions: list[Partition] = []

    partition_names, partition_statuses = await asyncio.gather(
        get_partition_names(protocol),
        get_partition_statuses(protocol),
    )

    for idx, p_name in partition_names.items():
        partitions.append(Partition(
            id = idx,
            name = p_name,
            status = partition_statuses.get(idx),
        ))

    return partitions


async def update_partition_statuses(protocol: Protocol, partitions: list[Partition]) -> list[Partition]:
    partition_statuses = await get_partition_statuses(protocol)

    for p in partitions:
        p.status = partition_statuses.get(p.id)

    return partitions
