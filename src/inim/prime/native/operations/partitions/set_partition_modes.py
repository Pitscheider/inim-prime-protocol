from typing import Final

from inim.prime.native.const import CommandOperation
from inim.prime.native.models import PartitionMode
from inim.prime.native.operations.partitions.const import PARTITIONS_MAX_NUMBER, PARTITION_MODE_REVERSE_MAP
from inim.prime.native.wire import Protocol
from inim.prime.native.wire.payload import CommandWithPinRequestPayload

### Constants
COMMAND_OPERATION: Final[CommandOperation] = CommandOperation.SET_PARTITION_MODES


### Functions
def assemble_data(partition_modes: dict[int, PartitionMode]) -> bytes:
    command_data = bytearray(PARTITIONS_MAX_NUMBER)

    for idx, partition_mode in partition_modes.items():
        if idx < 1 or idx > PARTITIONS_MAX_NUMBER:
            raise IndexError(f'Partition mode {idx} out of range')

        command_data[idx - 1] = PARTITION_MODE_REVERSE_MAP[partition_mode]

    return command_data


def assemble_payload(partition_modes: dict[int, PartitionMode], pin: str | None = None) -> bytes:
    return CommandWithPinRequestPayload.assemble(
        COMMAND_OPERATION,
        data = assemble_data(partition_modes),
        pin = pin,
    )


async def set_partition_modes(
        protocol: Protocol,
        partition_modes: dict[int, PartitionMode],
        pin: str | None = None,
) -> None:

    await protocol.execute_command_with_pin(
        operation = COMMAND_OPERATION,
        data = assemble_data(partition_modes),
        pin = pin,
    )