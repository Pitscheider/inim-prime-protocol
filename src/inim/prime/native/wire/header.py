from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Self

from inim.prime.native.const import Encoding, FrameOperation
from inim.prime.native.utils import next_slice


@dataclass(slots = True)
class Header(ABC):
    SIZE: ClassVar[int]

    @property
    @abstractmethod
    def inner_body_length(self) -> int:
        ...

    @classmethod
    @abstractmethod
    def from_bytes(
            cls,
            header: bytes
    ) -> Self:
        ...

    @property
    @abstractmethod
    def raw_bytes(self) -> bytes:
        ...


@dataclass(slots = True)
class OuterHeader(Header):

    ### Constants
    SIZE: ClassVar[int] = 12
    MAGIC: ClassVar[bytes] = b"\x50\x53"
    RESPONSE_INNER_FRAME_LENGTH_DEFAULT: ClassVar[int] = 0

    @dataclass(frozen = True)
    class _Layout:
        magic_size: int
        padding_size: int
        inner_frame_length_size: int
        response_inner_frame_length_size: int

        @property
        def magic(self) -> slice:
            return next_slice(0, self.magic_size)

        @property
        def padding(self) -> slice:
            return next_slice(self.magic, self.padding_size)

        @property
        def inner_frame_length(self) -> slice:
            return next_slice(self.padding, self.inner_frame_length_size)

        @property
        def response_inner_frame_length(self) -> slice:
            return next_slice(self.inner_frame_length, self.response_inner_frame_length_size)

    LAYOUTS: ClassVar[_Layout] = _Layout(
        magic_size = 2,
        padding_size = 2,
        inner_frame_length_size = Encoding.UINT32_LE_SIZE,
        response_inner_frame_length_size = Encoding.UINT32_LE_SIZE,
    )


    ### Attributes
    # Magic                        [0:2]     0x50 0x53       raw
    # Padding                      [2:4]     0-initialised   raw
    # Inner frame length           [4:8]     0-initialised   uint32 LE
    # Response inner frame length  [8:12]    0-initialised   uint32 LE
    magic: bytes = MAGIC
    padding: bytes = bytes(LAYOUTS.padding_size)
    inner_frame_length: bytes = bytes(LAYOUTS.inner_frame_length_size)
    response_inner_frame_length: bytes = bytes(LAYOUTS.response_inner_frame_length_size)


    ### Constructors
    @classmethod
    def build(
            cls,
            inner_frame_length: int,
            response_inner_frame_length: int,
    ) -> Self:
        outer_header = cls()
        outer_header.inner_frame_length_int = inner_frame_length
        outer_header.response_inner_frame_length_int = response_inner_frame_length
        return outer_header

    @classmethod
    def from_bytes(
            cls,
            outer_header: bytes
    ) -> Self:
        return cls(
            magic = outer_header[cls.LAYOUTS.magic],
            padding = outer_header[cls.LAYOUTS.padding],
            inner_frame_length = outer_header[cls.LAYOUTS.inner_frame_length],
            response_inner_frame_length = outer_header[cls.LAYOUTS.response_inner_frame_length],
        )


    ### Properties
    ## Header
    @property
    def inner_body_length(self) -> int:
        return self.inner_frame_length_int

    ## Helper
    @property
    def inner_frame_length_int(self) -> int:
        return struct.unpack(Encoding.UINT32_LE, self.inner_frame_length)[0]

    @inner_frame_length_int.setter
    def inner_frame_length_int(self, value: int) -> None:
        self.inner_frame_length = struct.pack(Encoding.UINT32_LE, value)

    @property
    def response_inner_frame_length_int(self) -> int:
        return struct.unpack(Encoding.UINT32_LE, self.response_inner_frame_length)[0]

    @response_inner_frame_length_int.setter
    def response_inner_frame_length_int(self, value: int) -> None:
        self.response_inner_frame_length = struct.pack(Encoding.UINT32_LE, value)

    ## Serialization
    @property
    def raw_bytes(self) -> bytes:
        return b"".join((
            self.magic,
            self.padding,
            self.inner_frame_length,
            self.response_inner_frame_length,
        ))

    ## Validation
    @property
    def is_magic_valid(self) -> bool:
        """True if magic bytes match 0x5053."""
        return self.magic == OuterHeader.MAGIC

    @property
    def is_padding_valid(self) -> bool:
        """True if padding bytes are 0x0000."""
        return self.padding == bytes(OuterHeader.LAYOUTS.padding_size)

    @property
    def is_valid(self) -> bool:
        """True if all validation checks pass."""
        return (
            self.is_magic_valid
            and self.is_padding_valid
        )


    ### To String
    def to_str(self, indent: int = 0) -> str:
        pad = " " * indent
        return (
            f"{pad}OuterHeader\n"
            f"{pad}  magic                        {self.magic.hex()}\n"
            f"{pad}  padding                      {self.padding.hex()}\n"
            f"{pad}  inner_frame_length           {self.inner_frame_length.hex():<12}  ({self.inner_frame_length_int})\n"
            f"{pad}  response_inner_frame_length  {self.response_inner_frame_length.hex():<12}  ({self.response_inner_frame_length_int})\n"
        )

    def __str__(self) -> str:
        return self.to_str()


    ### Methods
    ## Validation
    def validate(self) -> None:
        """
        Validates raising ValueError on the first failed check.
        :raises ValueError: If a checked property fails the check.
        """
        if not self.is_magic_valid:
            raise ValueError(
                f"Outer header magic mismatch: expected {OuterHeader.MAGIC.hex()}, "
                f"got {self.magic.hex()}."
            )
        if not self.is_padding_valid:
            raise ValueError(
                f"Outer header padding mismatch: expected {bytes(OuterHeader.LAYOUTS.padding_size).hex()}, "
                f"got {self.padding.hex()}."
            )


@dataclass(slots = True)
class InnerHeader(Header):

    ### Constants
    @dataclass(frozen = True)
    class _Layout:
        magic_size: int
        crc_size: int
        operation_size: int
        inner_frame_length_size: int

        @property
        def magic(self) -> slice:
            return next_slice(0, self.magic_size)

        @property
        def crc(self) -> slice:
            return next_slice(self.magic, self.crc_size)

        @property
        def operation(self) -> slice:
            return next_slice(self.crc, self.operation_size)

        @property
        def inner_frame_length(self) -> slice:
            return next_slice(self.operation, self.inner_frame_length_size)

    LAYOUTS: ClassVar[_Layout] = _Layout(
        magic_size = 2,
        crc_size = Encoding.UINT16_LE_SIZE,
        operation_size = Encoding.UINT16_LE_SIZE,
        inner_frame_length_size = Encoding.UINT32_LE_SIZE,
    )

    SIZE: ClassVar[int] = 10
    MAGIC: ClassVar[bytes] = b"\x50\x50"
    CRC_COVERAGE: ClassVar[slice] = slice(LAYOUTS.operation.start, SIZE)


    ### Attributes
    # Magic                 [0:2]     0x50 0x50       raw
    # CRC-16/ARC            [2:4]     0-initialised   uint16 LE
    # FrameOperation             [4:6]     0-initialised   raw
    # Inner frame length    [6:10]    0-initialised   uint32 LE
    magic: bytes = MAGIC
    crc: bytes = bytes(LAYOUTS.crc_size)
    operation: bytes = bytes(LAYOUTS.operation_size)
    inner_frame_length: bytes = bytes(LAYOUTS.inner_frame_length_size)


    ### Constructors
    @classmethod
    def build(
            cls,
            operation: FrameOperation,
            inner_frame_length: int,
    ) -> Self:
        inner_header = cls()
        inner_header.operation_enum = operation
        inner_header.inner_frame_length_int = inner_frame_length

        return inner_header

    @classmethod
    def from_bytes(
            cls,
            inner_header: bytes
    ) -> Self:
        return cls(
            magic = inner_header[cls.LAYOUTS.magic],
            crc = inner_header[cls.LAYOUTS.crc],
            operation = inner_header[cls.LAYOUTS.operation],
            inner_frame_length = inner_header[cls.LAYOUTS.inner_frame_length],
        )


    ### Properties
    ## Header
    @property
    def inner_body_length(self) -> int:
        return self.inner_frame_length_int - self.SIZE

    ## Helper
    @property
    def inner_frame_length_int(self) -> int:
        return struct.unpack(Encoding.UINT32_LE, self.inner_frame_length)[0]

    @inner_frame_length_int.setter
    def inner_frame_length_int(self, value: int) -> None:
        self.inner_frame_length = struct.pack(Encoding.UINT32_LE, value)

    @property
    def crc_int(self) -> int:
        """Inner header CRC value as an integer (uint16 LE)."""
        return struct.unpack(Encoding.UINT16_LE, self.crc)[0]

    @crc_int.setter
    def crc_int(self, value: int) -> None:
        self.crc = struct.pack(Encoding.UINT16_LE, value)

    @property
    def operation_enum(self) -> FrameOperation | None:
        """Return operation as enum."""
        try:
            return FrameOperation(self.operation)
        except ValueError:
            raise ValueError(f"Unknown operation: {self.operation.hex()}")

    @operation_enum.setter
    def operation_enum(self, operation: FrameOperation) -> None:
        self.operation = operation.value

    @property
    def operation_str(self) -> str:
        try:
            op = self.operation_enum
            assert op is not None
            return op.name
        except ValueError:
            return "UNKNOWN"

    ## Serialization
    @property
    def raw_bytes(self) -> bytes:
        return b"".join((
            self.magic,
            self.crc,
            self.operation,
            self.inner_frame_length,
        ))

    ## Validation
    @property
    def is_magic_valid(self) -> bool:
        """True if magic bytes match 0x5050."""
        return self.magic == InnerHeader.MAGIC

    @property
    def is_valid(self) -> bool:
        """True if all validation checks pass."""
        return (
            self.is_magic_valid
        )


    ## To String
    def to_str(self, indent: int = 0) -> str:
        pad = " " * indent
        return (
            f"{pad}InnerHeader\n"
            f"{pad}  magic                      {self.magic.hex()}\n"
            f"{pad}  crc                        {self.crc.hex():<12}  (0x{self.crc_int:04X})\n"
            f"{pad}  operation                  {self.operation.hex()} ({self.operation_str})\n"
            f"{pad}  inner_frame_length         {self.inner_frame_length.hex():<12}  ({self.inner_frame_length_int})\n"
        )

    def __str__(self) -> str:
        return self.to_str()


    ### Methods
    ## Validation
    def validate(self) -> None:
        """
        Validates the frame raising ValueError on the first failed check.
        :raises ValueError: If a checked property fails the check.
        """
        if not self.is_magic_valid:
            raise ValueError(
                f"Inner header magic mismatch: expected {InnerHeader.MAGIC.hex()}, "
                f"got {self.magic.hex()}."
            )
