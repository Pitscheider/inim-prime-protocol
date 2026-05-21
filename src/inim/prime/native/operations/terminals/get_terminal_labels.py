from typing import Final

from inim.prime.native.const import Memory, AddressTable
from inim.prime.native.operations import resolve_address
from inim.prime.native.operations.terminals.const import TerminalType, TERMINALS_MAX_NUMBER
from inim.prime.native.utils import next_slice
from inim.prime.native.wire import Protocol


### Constants
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
            layout[previous] if previous is not None else 0 + offset,
            TERMINAL_LABEL_SIZES[t],
        )
        previous = t

    return layout

TERMINAL_LABEL_SIZES: Final[dict[TerminalType, int]] = _build_terminal_label_sizes()
TERMINAL_LABEL_LAYOUTS: Final[dict[TerminalType, slice]] = _build_terminal_label_layouts()
TERMINAL_LABEL_DEFAULT_LAYOUTS: Final[dict[TerminalType, slice]] = _build_terminal_label_layouts(TERMINAL_LABEL_LAYOUTS[TerminalType.VIRTUAL].stop)


### Functions
async def get_terminal_labels(
        protocol: Protocol,
        terminal_type: TerminalType,
) -> dict[int, str]:

    address = await resolve_address(protocol, AddressTable.GET_TERMINAL_LABELS)

    layout = TERMINAL_LABEL_LAYOUTS[terminal_type]
    size = TERMINAL_LABEL_SIZES[terminal_type]

    response = await protocol.read_memory(address + layout.start, size)

    terminals = {}

    for idx, offset in enumerate(
            range(0, size, Memory.LABEL_SIZE),
            start = 1,
    ):
        label = response[offset:offset + Memory.LABEL_SIZE]
        terminals[idx] = label.decode("ascii").strip()
    return terminals
