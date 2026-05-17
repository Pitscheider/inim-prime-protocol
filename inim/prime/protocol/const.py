from __future__ import annotations

from enum import Enum
from typing import Final


class Encoding:
    UINT8: Final[str] = "B"
    UINT16_LE: Final[str] = "<H"
    UINT32_LE: Final[str] = "<I"
    UINT64_LE: Final[str] = "<Q"


class CommandOperation(Enum):
    SET_PARTITION_MODES = 3
    GET_PARTITION_STATUSES = 6
    RESET_PARTITIONS = 16
    GET_PANEL_INFO = 23


class Panel:
    DEFAULT_PORT: Final[int] = 6004
    DEFAULT_PASSWORD: Final[str] = "pass"

    class DefaultMasterPin:
        """Sentinel type for the hardcoded master PIN."""
        BYTES: bytes = bytes([0x74, 0x00, 0x00, 0x00, 0x00, 0x00])

        def __bytes__(self) -> bytes:
            return self.BYTES

        def __repr__(self) -> str:
            return "DEFAULT_MASTER_PIN"

    DEFAULT_MASTER_PIN: Final[DefaultMasterPin] = DefaultMasterPin()


class AddressTable:
    ENTRY_SIZE: Final[int] = 4

    GET_PARTITION_LABELS: Final[int] = 436216852
    GET_TERMINAL_LABELS: Final[int] = 436216856

class Memory:
    LABEL_SIZE: Final[int] = 16

