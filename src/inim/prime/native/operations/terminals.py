from enum import StrEnum, auto

from inim.prime.native.const import AddressTable, Memory
from inim.prime.native.wire import Protocol

from . import resolve_address
from ..utils import next_slice


class TerminalType(StrEnum):
    PANEL = auto()
    EXPANSION = auto()
    KEYPAD = auto()
    TEMPERATURE_PROBE = auto()
    ROLLER_BLINDS = auto()
    PROXIMITY_KEY_READER = auto()
    BUS_SENSOR = auto()
    VIDEO_SENSOR = auto()
    POWER_STATION = auto()
    FOG_MACHINE = auto()
    VIRTUAL = auto()

TERMINALS_MAX_NUMBER: dict[TerminalType, int] = {
    TerminalType.PANEL: 10,
    TerminalType.EXPANSION: 100 * 5,
    TerminalType.KEYPAD: 30 * 2,
    TerminalType.TEMPERATURE_PROBE: 15,
    TerminalType.ROLLER_BLINDS: 30 * 4,
    TerminalType.PROXIMITY_KEY_READER: 60,
    TerminalType.BUS_SENSOR: 180,
    TerminalType.VIDEO_SENSOR: 10,
    TerminalType.POWER_STATION: 10 * 2,
    TerminalType.FOG_MACHINE: 10,
    TerminalType.VIRTUAL: 20,
}

def _build_terminal_label_sizes() -> dict[TerminalType, int]:
    size: dict[TerminalType, int] = {}
    for t in TerminalType:
        size[t] = TERMINALS_MAX_NUMBER[t] * Memory.LABEL_SIZE
    return size

def _build_terminal_label_layouts(offset: int = 0) -> dict[TerminalType, slice]:
    layout: dict[TerminalType, slice] = {}

    previous: TerminalType | None = None
    for t in TerminalType:
        layout[t] = next_slice(
            layout[previous] if previous is not None else 0,
            TERMINAL_LABEL_SIZES[t],
        )
        previous = t

    return layout



TERMINAL_LABEL_SIZES = _build_terminal_label_sizes()
TERMINAL_LABEL_LAYOUTS: dict[TerminalType, slice] = _build_terminal_label_layouts()
TERMINAL_LABEL_DEFAULT_LAYOUTS: dict[TerminalType, slice] = _build_terminal_label_layouts(TERMINAL_LABEL_LAYOUTS[TerminalType.VIRTUAL].stop)


async def get_terminal_labels(
        protocol: Protocol,
        terminal_type: TerminalType,
) -> dict[int, str]:

    address = await resolve_address(protocol, AddressTable.GET_TERMINAL_LABELS)

    layout = TERMINAL_LABEL_LAYOUTS[terminal_type]
    size = TERMINAL_LABEL_SIZES[terminal_type]

    response = await protocol.read_memory(address + layout.start, size)

    panel_terminals = {}

    for idx, offset in enumerate(
            range(0, size, Memory.LABEL_SIZE),
            start = 1,
    ):
        label = response[offset:offset + Memory.LABEL_SIZE]
        panel_terminals[idx] = label.decode("ascii").strip()
    return panel_terminals