from __future__ import annotations

import struct
from abc import abstractmethod, ABC
from dataclasses import dataclass
from typing import ClassVar, Self

from prime.protocol.const import Encoding, CommandOperation, Panel


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    """Simple 8-bit additive checksum (sum of all bytes, truncated to 1 byte)."""
    return sum(data) & 0xFF


# ---------------------------------------------------------------------------
# Abstract base — contract every payload must honour
# ---------------------------------------------------------------------------

class BasePayload(ABC):
    """
    Shared contract for all Inim payload types.

    Every concrete payload must be able to:
      - Serialise itself to bytes          (raw_bytes / to_bytes)
      - Parse itself from bytes            (from_bytes)
      - Build from logical parameters      (build / assemble)
      - Extract meaningful content         (disassemble)

    Checksum handling is NOT part of this contract — that lives in
    ChecksummedPayload, which only read payloads inherit from.
    """

    @property
    @abstractmethod
    def raw_bytes(self) -> bytes:
        """All fields in wire order, without recomputing any integrity value."""
        ...

    def to_bytes(self) -> bytes:
        """
        Serialise the payload to bytes, finalising any integrity fields first.
        Default implementation delegates straight to raw_bytes.
        Overridden by ChecksummedPayload to update the checksum before returning.
        """
        return self.raw_bytes

    @classmethod
    @abstractmethod
    def from_bytes(cls, raw: bytes) -> Self:
        """
        Parse raw bytes into a payload instance.
        Must not validate integrity — call validate() separately if needed.
        """
        ...

    @classmethod
    @abstractmethod
    def build(cls, **kwargs) -> Self:
        """Construct a payload instance from logical parameters."""
        ...

    @classmethod
    @abstractmethod
    def assemble(cls, **kwargs) -> bytes:
        """
        Build a payload from logical parameters and return wire bytes.
        Convenience shortcut for build(...).to_bytes().
        Each subclass declares its own typed parameter list.
        """
        ...

    @classmethod
    @abstractmethod
    def disassemble(cls, raw: bytes) -> object:
        """
        Parse raw bytes and return meaningful content.
        Validates integrity if applicable.
        Concrete subclasses narrow the return type to their specific output.
        """
        ...


# ---------------------------------------------------------------------------
# Mixin — checksum behaviour, shared by all read payloads
# ---------------------------------------------------------------------------

class ChecksummedPayload(BasePayload, ABC):
    """
    Extends BasePayload with an 8-bit additive checksum appended as the last byte.

    Subclasses must:
      - Store `checksum: bytes` as a dataclass field (1 byte, 0-initialised).
      - Override `CHECKSUM_COVERAGE` to define the slice that the checksum covers.
      - Override `raw_bytes` to include `self.checksum` as the last element.
      - Override `from_bytes` to parse raw bytes into an instance.
      - Override `assemble` with their own typed parameter list.

    disassemble is provided here as a concrete implementation —
    subclasses only need to override it if their meaningful content
    is something other than the raw validated bytes.
    """

    class Layout:
        CHECKSUM_SIZE: ClassVar[int] = 1

    CHECKSUM_COVERAGE: ClassVar[slice]  # subclasses define the exact coverage

    # ------------------------------------------------------------------
    # Checksum accessors
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def checksum(self) -> bytes:
        """Subclasses must store this as a dataclass field."""
        ...

    @checksum.setter
    @abstractmethod
    def checksum(self, value: bytes) -> None:
        """Subclasses must store this as a dataclass field."""
        ...

    @property
    def checksum_int(self) -> int:
        return struct.unpack(Encoding.UINT8, self.checksum)[0]  # type: ignore[attr-defined]

    @checksum_int.setter
    def checksum_int(self, value: int) -> None:
        self.checksum = struct.pack(Encoding.UINT8, value)  # type: ignore[attr-defined]

    def calculate_checksum(self) -> int:
        """Computes the checksum over CHECKSUM_COVERAGE of the current raw bytes."""
        return _checksum(self.raw_bytes[self.CHECKSUM_COVERAGE])

    def update_checksum(self) -> None:
        """Writes the computed checksum into the checksum field."""
        self.checksum_int = self.calculate_checksum()

    @property
    def is_checksum_valid(self) -> bool:
        return self.checksum_int == self.calculate_checksum()

    def validate(self) -> Self:
        """
        :raises ValueError: If the stored checksum does not match the computed one.
        """
        if not self.is_checksum_valid:
            raise ValueError(
                f"Checksum mismatch: declared {self.checksum_int}, "
                f"computed {self.calculate_checksum()}."
            )
        return self

    def to_bytes(self) -> bytes:
        """Updates the checksum field, then returns the wire bytes."""
        self.update_checksum()
        return self.raw_bytes


# ---------------------------------------------------------------------------
# Read payloads  (checksum present, by Inim wire design)
# ---------------------------------------------------------------------------

@dataclass(slots = True)
class ReadRequestPayload(ChecksummedPayload):
    """
    Plaintext payload for a memory read request.

    Wire layout (20 bytes):
      Address               [0:8]    uint64 LE
      Chunk length echo     [8:12]   uint32 LE   (mirrors chunk_length)
      Chunk length          [12:16]  uint32 LE
      Padding               [16:18]  0x0000
      Marker                [18:19]  0x11
      Checksum              [19:20]  uint8        covers [0:19]
    """

    class Layout:
        ADDRESS: ClassVar[slice] = slice(0, 8)
        CHUNK_LENGTH_ECHO: ClassVar[slice] = slice(8, 12)
        CHUNK_LENGTH: ClassVar[slice] = slice(12, 16)
        PADDING: ClassVar[slice] = slice(16, 18)
        MARKER: ClassVar[slice] = slice(18, 19)
        CHECKSUM: ClassVar[slice] = slice(19, 20)

        ADDRESS_SIZE: ClassVar[int] = ADDRESS.stop - ADDRESS.start
        CHUNK_LENGTH_ECHO_SIZE: ClassVar[int] = CHUNK_LENGTH_ECHO.stop - CHUNK_LENGTH_ECHO.start
        CHUNK_LENGTH_SIZE: ClassVar[int] = CHUNK_LENGTH.stop - CHUNK_LENGTH.start
        PADDING_SIZE: ClassVar[int] = PADDING.stop - PADDING.start
        MARKER_SIZE: ClassVar[int] = MARKER.stop - MARKER.start
        CHECKSUM_SIZE: ClassVar[int] = CHECKSUM.stop - CHECKSUM.start

    MARKER: ClassVar[bytes] = b"\x11"
    CHECKSUM_COVERAGE: ClassVar[slice] = slice(Layout.ADDRESS.start, Layout.MARKER.stop)

    address: bytes = bytes(Layout.ADDRESS_SIZE)
    chunk_length_echo: bytes = bytes(Layout.CHUNK_LENGTH_ECHO_SIZE)
    chunk_length: bytes = bytes(Layout.CHUNK_LENGTH_SIZE)
    padding: bytes = bytes(Layout.PADDING_SIZE)
    marker: bytes = MARKER
    checksum: bytes = bytes(Layout.CHECKSUM_SIZE)

    # ------------------------------------------------------------------
    # High-level entry points
    # ------------------------------------------------------------------

    @classmethod
    def assemble(cls, address: int, chunk_length: int) -> bytes:
        """Builds the payload, computes its checksum, and returns the wire bytes."""
        return cls.build(address = address, chunk_length = chunk_length).to_bytes()

    @classmethod
    def disassemble(cls, raw: bytes) -> tuple[int, int]:
        """
        Validates the checksum and returns the parsed fields.
        :param raw:     Raw read request payload bytes.
        :return:        (address, chunk_length) as integers.
        :raises ValueError: If the checksum is invalid.
        """
        instance = cls.from_bytes(raw)
        instance.validate()
        return instance.address_int, instance.chunk_length_int

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def build(cls, address: int, chunk_length: int) -> Self:
        """Constructs a payload object from logical parameters. Checksum is 0-initialised."""
        instance = cls()
        instance.address_int = address
        instance.chunk_length_echo_int = chunk_length
        instance.chunk_length_int = chunk_length
        return instance

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        """Parses raw bytes into a payload object. Does not validate the checksum."""
        return cls(
            address = raw[cls.Layout.ADDRESS],
            chunk_length_echo = raw[cls.Layout.CHUNK_LENGTH_ECHO],
            chunk_length = raw[cls.Layout.CHUNK_LENGTH],
            padding = raw[cls.Layout.PADDING],
            marker = raw[cls.Layout.MARKER],
            checksum = raw[cls.Layout.CHECKSUM],
        )

    # ------------------------------------------------------------------
    # Typed field accessors
    # ------------------------------------------------------------------

    @property
    def address_int(self) -> int:
        return struct.unpack(Encoding.UINT64_LE, self.address)[0]

    @address_int.setter
    def address_int(self, value: int) -> None:
        self.address = struct.pack(Encoding.UINT64_LE, value)

    @property
    def chunk_length_echo_int(self) -> int:
        return struct.unpack(Encoding.UINT32_LE, self.chunk_length_echo)[0]

    @chunk_length_echo_int.setter
    def chunk_length_echo_int(self, value: int) -> None:
        self.chunk_length_echo = struct.pack(Encoding.UINT32_LE, value)

    @property
    def chunk_length_int(self) -> int:
        return struct.unpack(Encoding.UINT32_LE, self.chunk_length)[0]

    @chunk_length_int.setter
    def chunk_length_int(self, value: int) -> None:
        self.chunk_length = struct.pack(Encoding.UINT32_LE, value)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @property
    def raw_bytes(self) -> bytes:
        return b"".join((
            self.address,
            self.chunk_length_echo,
            self.chunk_length,
            self.padding,
            self.marker,
            self.checksum,
        ))


@dataclass(slots = True)
class ReadResponsePayload(ChecksummedPayload):
    """
    Plaintext payload for a memory read response.

    Wire layout (dynamic length):
      Data      [0 : n]     raw bytes
      Checksum  [n : n+1]   uint8       covers [0:n]
    """

    class Layout:
        DATA: ClassVar[slice] = slice(0, -1)
        CHECKSUM: ClassVar[slice] = slice(-1, None)

    CHECKSUM_COVERAGE: ClassVar[slice] = slice(0, -1)  # everything except the last byte

    data: bytes = b""
    checksum: bytes = bytes(1)

    # ------------------------------------------------------------------
    # High-level entry points
    # ------------------------------------------------------------------

    @classmethod
    def assemble(cls, data: bytes) -> bytes:
        """Wraps data with a checksum and returns the wire bytes."""
        return cls.build(data = data).to_bytes()

    @classmethod
    def disassemble(cls, raw: bytes) -> bytes:
        """
        Validates the checksum and returns the data without it.
        :param raw:         Raw read response payload bytes.
        :return:            Data bytes, without checksum.
        :raises ValueError: If the checksum is invalid.
        """
        return cls.from_bytes(raw).validate().data

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def build(cls, data: bytes) -> Self:
        """Constructs a payload object from logical parameters. Checksum is 0-initialised."""
        return cls(data = data)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        """Parses raw bytes into a payload object. Does not validate the checksum."""
        return cls(
            data = raw[cls.Layout.DATA],
            checksum = raw[cls.Layout.CHECKSUM],
        )

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @property
    def raw_bytes(self) -> bytes:
        return b"".join((self.data, self.checksum))


# ---------------------------------------------------------------------------
# Command payloads  (no checksum, by Inim wire design)
# ---------------------------------------------------------------------------

@dataclass(slots = True)
class CommandRequestPayload(BasePayload):
    """
    Plaintext payload for a command request.

    Wire layout (variable length):
      Operation   [0:4]    uint32 LE
      PIN         [4:10]   6 bytes, digit-per-byte, 0xFF-padded; or PIN_ABSENT
      Data        [10:]    operation-specific bytes (may be empty)

    Note: command payloads carry no checksum — this is by Inim wire design.
    """

    class Layout:
        OPERATION: ClassVar[slice] = slice(0, 4)
        PIN: ClassVar[slice] = slice(4, 10)
        DATA: ClassVar[slice] = slice(10, None)

        OPERATION_SIZE: ClassVar[int] = OPERATION.stop - OPERATION.start
        PIN_SIZE: ClassVar[int] = PIN.stop - PIN.start

    PIN_PADDING: ClassVar[int] = 0xFF

    operation: bytes = bytes(Layout.OPERATION_SIZE)
    pin: bytes = b""
    data: bytes = b""

    # ------------------------------------------------------------------
    # High-level entry points
    # ------------------------------------------------------------------

    @classmethod
    def assemble(
            cls,
            operation: CommandOperation,
            data: bytes | None = None,
            pin: str | None | Panel.DefaultMasterPin = Panel.DefaultMasterPin(),
    ) -> bytes:
        """Builds the payload and returns the wire bytes. No checksum is applied."""
        return cls.build(operation = operation, data = data, pin = pin).to_bytes()

    @classmethod
    def disassemble(cls, raw: bytes) -> tuple[CommandOperation, bytes | None, str | None | Panel.DefaultMasterPin]:
        """
        Parses a raw command request payload.
        :param raw: Raw command request payload bytes.
        :return:    (operation, data, pin) tuple.
        """
        instance = cls.from_bytes(raw)
        return instance.operation_enum, instance.data or None, instance.pin_str

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    def build(
            cls,
            operation: CommandOperation,
            data: bytes | None = None,
            pin: str | None | Panel.DefaultMasterPin = Panel.DEFAULT_MASTER_PIN,
    ) -> Self:
        """Constructs a payload object from logical parameters."""
        payload = cls()
        payload.operation_enum = operation
        if isinstance(pin, Panel.DefaultMasterPin):
            payload.pin = bytes(pin)
        elif pin is not None:
            payload.pin_str = pin
        if data is not None:
            payload.data = data
        return payload

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        """Parses raw bytes into a payload object."""
        return cls(
            operation = raw[cls.Layout.OPERATION],
            pin = raw[cls.Layout.PIN],
            data = raw[cls.Layout.DATA],
        )

    # ------------------------------------------------------------------
    # Typed field accessors
    # ------------------------------------------------------------------

    @property
    def operation_int(self) -> int:
        return struct.unpack(Encoding.UINT32_LE, self.operation)[0]

    @operation_int.setter
    def operation_int(self, value: int) -> None:
        self.operation = struct.pack(Encoding.UINT32_LE, value)

    @property
    def operation_enum(self) -> CommandOperation:
        try:
            return CommandOperation(self.operation_int)
        except ValueError:
            raise ValueError(f"Unknown operation: {self.operation.hex()}")

    @operation_enum.setter
    def operation_enum(self, operation: CommandOperation) -> None:
        self.operation = struct.pack(Encoding.UINT32_LE, operation.value)

    @property
    def pin_str(self) -> str | None | Panel.DefaultMasterPin:
        if self.pin == bytes(Panel.DEFAULT_MASTER_PIN):
            return Panel.DEFAULT_MASTER_PIN
        if not self.pin:
            return None
        return self._decode_pin()

    @pin_str.setter
    def pin_str(self, pin: str) -> None:
        if not pin.isdigit():
            raise ValueError(f"PIN must contain digits only, got: {pin!r}")
        if not (1 <= len(pin) <= self.Layout.PIN_SIZE):
            raise ValueError(f"PIN must be 1–{self.Layout.PIN_SIZE} digits, got {len(pin)}.")
        encoded = [int(d) for d in pin]
        encoded += [self.PIN_PADDING] * (self.Layout.PIN_SIZE - len(pin))
        self.pin = bytes(encoded)

    def _decode_pin(self) -> str:
        digits = []
        for byte in self.pin:
            if byte == self.PIN_PADDING:
                break
            if byte > 9:
                raise ValueError(f"Invalid PIN byte: 0x{byte:02X}.")
            digits.append(str(byte))
        if not digits:
            raise ValueError(f"No valid digits found in PIN: {self.pin.hex(' ')}.")
        return "".join(digits)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    @property
    def raw_bytes(self) -> bytes:
        return b"".join((self.operation, self.pin, self.data))


# ---------------------------------------------------------------------------
# Command response placeholder
# ---------------------------------------------------------------------------

@dataclass(slots = True)
class CommandResponsePayload(BasePayload):
    """
    Plaintext payload for a command response.

    Note: command payloads carry no checksum — this is by Inim wire design.

    TODO: The response envelope is not yet decoded.
          For now the raw bytes are stored as-is and returned to the caller.
    """

    data: bytes = b""

    @classmethod
    def build(cls, data: bytes) -> Self:
        return cls(data = data)

    @classmethod
    def assemble(cls, data: bytes) -> bytes:
        return cls.build(data).to_bytes()

    @classmethod
    def disassemble(cls, raw: bytes) -> bytes:
        """Parses a raw response and returns the payload data."""
        return cls.from_bytes(raw).data

    @classmethod
    def from_bytes(cls, raw: bytes) -> Self:
        return cls(data = raw)

    @property
    def raw_bytes(self) -> bytes:
        return self.data
