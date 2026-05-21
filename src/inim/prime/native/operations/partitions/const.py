from typing import Final

from inim.prime.native.models import PartitionMode

PARTITIONS_MAX_NUMBER: Final[int] = 30

PARTITION_MODE_MAP = {
    0x01: PartitionMode.TOTAL,
    0x02: PartitionMode.PARTIAL,
    0x03: PartitionMode.INSTANT,
    0x04: PartitionMode.DISARMED,
}

PARTITION_MODE_REVERSE_MAP = {
    value: key for key, value in PARTITION_MODE_MAP.items()
}