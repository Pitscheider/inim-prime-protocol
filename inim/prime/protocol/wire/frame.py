from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum
from typing import Self, ClassVar, Final

from prime.protocol.const import Encoding
from .cipher import Cipher

"""
CRC-16/ARC lookup table
Algorithm:  CRC-16/ARC (also known as CRC-16/IBM, CRC-16/LHA, CRC-16)
Polynomial: 0x8005 (reflected: 0xC0C1)
Parameters: init=0x0000, refin=True, refout=True, xorout=0x0000
"""
CRC16_TABLE: Final[tuple[int, ...]] = (
    0, 49345, 49537, 320, 49921, 960, 640, 49729, 50689, 1728, 1920, 51009, 1280, 50625, 50305, 1088,
    52225, 3264, 3456, 52545, 3840, 53185, 52865, 3648, 2560, 51905, 52097, 2880, 51457, 2496, 2176, 51265,
    55297, 6336, 6528, 55617, 6912, 56257, 55937, 6720, 7680, 57025, 57217, 8000, 56577, 7616, 7296, 56385,
    5120, 54465, 54657, 5440, 55041, 6080, 5760, 54849, 53761, 4800, 4992, 54081, 4352, 53697, 53377, 4160,
    61441, 12480, 12672, 61761, 13056, 62401, 62081, 12864, 13824, 63169, 63361, 14144, 62721, 13760, 13440, 62529,
    15360, 64705, 64897, 15680, 65281, 16320, 16000, 65089, 64001, 15040, 15232, 64321, 14592, 63937, 63617, 14400,
    10240, 59585, 59777, 10560, 60161, 11200, 10880, 59969, 60929, 11968, 12160, 61249, 11520, 60865, 60545, 11328,
    58369, 9408, 9600, 58689, 9984, 59329, 59009, 9792, 8704, 58049, 58241, 9024, 57601, 8640, 8320, 57409,
    40961, 24768, 24960, 41281, 25344, 41921, 41601, 25152, 26112, 42689, 42881, 26432, 42241, 26048, 25728, 42049,
    27648, 44225, 44417, 27968, 44801, 28608, 28288, 44609, 43521, 27328, 27520, 43841, 26880, 43457, 43137, 26688,
    30720, 47297, 47489, 31040, 47873, 31680, 31360, 47681, 48641, 32448, 32640, 48961, 32000, 48577, 48257, 31808,
    46081, 29888, 30080, 46401, 30464, 47041, 46721, 30272, 29184, 45761, 45953, 29504, 45313, 29120, 28800, 45121,
    20480, 37057, 37249, 20800, 37633, 21440, 21120, 37441, 38401, 22208, 22400, 38721, 21760, 38337, 38017, 21568,
    39937, 23744, 23936, 40257, 24320, 40897, 40577, 24128, 23040, 39617, 39809, 23360, 39169, 22976, 22656, 38977,
    34817, 18624, 18816, 35137, 19200, 35777, 35457, 19008, 19968, 36545, 36737, 20288, 36097, 19904, 19584, 35905,
    17408, 33985, 34177, 17728, 34561, 18368, 18048, 34369, 33281, 17088, 17280, 33601, 16640, 33217, 32897, 16448,
)


def _round_up_to_block(
        n: int,
        block: int = Cipher.AES_BLOCK_SIZE,
) -> int:
    """
    Rounds up a number to the nearest multiple of the specified block that is greater or equal than it.
    :param n:       The number to round up.
    :param block:   Value of the multiplier used to round up the number.
                    Defaults to AES block size (16 bytes).
    :return:        The rounded up number.
    """
    return ((n + block - 1) // block) * block


def _crc16_arc(
        data: bytes | bytearray,
) -> int:
    """
    Computes CRC-16/ARC checksum over data.
    :param data:   The data to compute CRC-16/ARC checksum over.
    :return:        The computed CRC-16/ARC checksum as a 16-bit integer (0–65535).
    """
    # Zero-initialised CRC value
    crc = 0

    for byte in data:
        # XOR the incoming byte with the low 8 bits of the running CRC
        # to produce a table index in range 0–255
        table_index = (crc ^ byte) & 0xFF

        # Retrieves the precomputed CRC value using the obtained table_index.
        table_value = CRC16_TABLE[table_index]

        # Takes the 8 most significant bits of CRC (the high byte)
        high_byte = (crc >> 8) & 0xFF

        # XOR the CRC high_byte with table_value
        crc = high_byte ^ table_value

    return crc & 0xFFFF


@dataclass(slots = True)
class Frame:
    ### Nested data classes
    @dataclass(slots = True)
    class OuterHeader:

        ### Constants
        SIZE: ClassVar[int] = 12
        MAGIC: ClassVar[bytes] = b"\x50\x53"
        RESPONSE_INNER_FRAME_LENGTH_DEFAULT: ClassVar[int] = 0

        class Layout:
            MAGIC: ClassVar[slice] = slice(0, 2)
            PADDING: ClassVar[slice] = slice(2, 4)
            INNER_FRAME_LENGTH: ClassVar[slice] = slice(4, 8)
            RESPONSE_INNER_FRAME_LENGTH: ClassVar[slice] = slice(8, 12)

            MAGIC_SIZE: ClassVar[int] = MAGIC.stop - MAGIC.start
            PADDING_SIZE: ClassVar[int] = PADDING.stop - PADDING.start
            INNER_FRAME_LENGTH_SIZE: ClassVar[int] = INNER_FRAME_LENGTH.stop - INNER_FRAME_LENGTH.start
            RESPONSE_INNER_FRAME_LENGTH_SIZE: ClassVar[
                int] = RESPONSE_INNER_FRAME_LENGTH.stop - RESPONSE_INNER_FRAME_LENGTH.start

        ### Attributes
        # Magic                        [0:2]     0x50 0x53       raw
        # Padding                      [2:4]     0-initialised   raw
        # Inner frame length           [4:8]     0-initialised   uint32 LE
        # Response inner frame length  [8:12]    0-initialised   uint32 LE
        magic: bytes = MAGIC
        padding: bytes = bytes(Layout.PADDING_SIZE)
        inner_frame_length: bytes = bytes(Layout.INNER_FRAME_LENGTH_SIZE)
        response_inner_frame_length: bytes = bytes(Layout.RESPONSE_INNER_FRAME_LENGTH_SIZE)

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
                magic = outer_header[cls.Layout.MAGIC],
                padding = outer_header[cls.Layout.PADDING],
                inner_frame_length = outer_header[cls.Layout.INNER_FRAME_LENGTH],
                response_inner_frame_length = outer_header[cls.Layout.RESPONSE_INNER_FRAME_LENGTH],
            )

        ### Properties
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

        @property
        def raw_bytes(self) -> bytes:
            return b"".join((
                self.magic,
                self.padding,
                self.inner_frame_length,
                self.response_inner_frame_length,
            ))

    @dataclass(slots = True)
    class InnerHeader:

        ### Constants
        class Layout:
            MAGIC: ClassVar[slice] = slice(0, 2)
            CRC: ClassVar[slice] = slice(2, 4)
            OPERATION: ClassVar[slice] = slice(4, 6)
            INNER_FRAME_LENGTH: ClassVar[slice] = slice(6, 10)

            MAGIC_SIZE: ClassVar[int] = MAGIC.stop - MAGIC.start
            CRC_SIZE: ClassVar[int] = CRC.stop - CRC.start
            OPERATION_SIZE: ClassVar[int] = OPERATION.stop - OPERATION.start
            INNER_FRAME_LENGTH_SIZE: ClassVar[int] = INNER_FRAME_LENGTH.stop - INNER_FRAME_LENGTH.start

        class Operation(bytes, Enum):
            READ = b"\x00\x00"
            COMMAND = b"\x01\x00"

        SIZE: ClassVar[int] = 10
        MAGIC: ClassVar[bytes] = b"\x50\x50"
        CRC_COVERAGE: ClassVar[slice] = slice(Layout.OPERATION.start, SIZE)

        ### Attributes
        # Magic                 [0:2]     0x50 0x50       raw
        # CRC-16/ARC            [2:4]     0-initialised   uint16 LE
        # Operation             [4:6]     0-initialised   raw
        # Inner frame length    [6:10]    0-initialised   uint32 LE
        magic: bytes = MAGIC
        crc: bytes = bytes(Layout.CRC_SIZE)
        operation: bytes = bytes(Layout.OPERATION_SIZE)
        inner_frame_length: bytes = bytes(Layout.INNER_FRAME_LENGTH_SIZE)

        ### Constructors
        @classmethod
        def build(
                cls,
                operation: Operation,
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
                magic = inner_header[cls.Layout.MAGIC],
                crc = inner_header[cls.Layout.CRC],
                operation = inner_header[cls.Layout.OPERATION],
                inner_frame_length = inner_header[cls.Layout.INNER_FRAME_LENGTH],
            )

        ### Properties
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
        def operation_enum(self) -> Operation | None:
            """Return operation as enum."""
            try:
                return self.Operation(self.operation)
            except ValueError:
                raise ValueError(f"Unknown operation: {self.operation.hex()}")

        @operation_enum.setter
        def operation_enum(self, operation: Operation) -> None:
            self.operation = operation.value

        @property
        def raw_bytes(self) -> bytes:
            return b"".join((
                self.magic,
                self.crc,
                self.operation,
                self.inner_frame_length,
            ))

        @property
        def operation_str(self) -> str:
            try:
                op = self.operation_enum
                assert op is not None
                return op.name
            except ValueError:
                return "UNKNOWN"

    ### Constants
    class Layout:
        OuterHeader: ClassVar[slice] = slice(0, 12)
        InnerHeader: ClassVar[slice] = slice(12, 22)
        EncryptedPayload: ClassVar[slice] = slice(22, None)

    MIN_SIZE: ClassVar[int] = OuterHeader.SIZE + InnerHeader.SIZE + Cipher.AES_BLOCK_SIZE
    CRC_COVERAGE: ClassVar[slice] = slice(OuterHeader.SIZE + InnerHeader.Layout.OPERATION.start, None)

    ### Attributes
    inner_header: InnerHeader  # [0:12]    Inner header
    outer_header: OuterHeader  # [12:22]   Outer header
    encrypted_payload: bytes  # [22: ]    Encrypted payload

    ### Main methods
    @classmethod
    def assemble(
            cls,
            encrypted_payload: bytes,
            operation: InnerHeader.Operation,
            response_payload_length: int | None = None,
    ) -> bytes:
        """
        Assembles a raw frame from meaningful parameters, computes CRC, and returns it as bytes.
        :param encrypted_payload:           AES-128-CBC ciphertext to embed.
        :param response_payload_length:     Expected length of the response plaintext payload.
        :param operation:                   Operation type.
        :return: The constructed frame as bytes.
        """
        frame = cls.build(
            encrypted_payload = encrypted_payload,
            response_payload_length = response_payload_length,
            operation = operation,
        )

        return frame.to_bytes()

    @classmethod
    def disassemble(
            cls,
            frame_bytes: bytes,
    ) -> bytes:
        """
        Disassembles a raw frame, validates its integrity, and returns the encrypted payload.
        :param frame_bytes: Raw frame bytes.
        :return:            The encrypted payload as bytes.
        :raises ValueError: If the validation of the frame fails.
        """
        frame = cls.from_bytes(frame_bytes)
        frame.validate()
        return frame.encrypted_payload

    ### Constructors
    @classmethod
    def build(
            cls,
            encrypted_payload: bytes,
            operation: InnerHeader.Operation,
            response_payload_length: int | None = None,
    ) -> Self:
        """
        Constructs a frame from meaningful parameters.
        CRC is 0-initialised.
        :param encrypted_payload:           AES-128-CBC ciphertext to embed.
        :param response_payload_length:     Expected length of the response plaintext payload.
        :param operation:                   Operation type.
        :return: The constructed frame object.
        """
        inner_frame_length = cls.InnerHeader.SIZE + len(encrypted_payload)
        if response_payload_length is not None:
            response_inner_frame_length = _round_up_to_block(response_payload_length) + Frame.InnerHeader.SIZE
        else:
            response_inner_frame_length = cls.OuterHeader.RESPONSE_INNER_FRAME_LENGTH_DEFAULT

        frame = cls(
            outer_header = cls.OuterHeader.build(
                inner_frame_length = inner_frame_length,
                response_inner_frame_length = response_inner_frame_length,
            ),
            inner_header = cls.InnerHeader.build(
                operation = operation,
                inner_frame_length = inner_frame_length,
            ),
            encrypted_payload = encrypted_payload,
        )

        return frame

    @classmethod
    def from_bytes(cls, frame_bytes: bytes) -> Self:
        """
        Parses a raw bytes frame into a Frame instance.
        Does not validate the frame.
        :param frame_bytes:     Raw bytes of the frame to parse.
        :return:                The constructed frame object.
        """
        outer_header = frame_bytes[cls.Layout.OuterHeader]
        inner_header = frame_bytes[cls.Layout.InnerHeader]
        encrypted_payload = frame_bytes[cls.Layout.EncryptedPayload]

        return cls(
            outer_header = cls.OuterHeader.from_bytes(outer_header),
            inner_header = cls.InnerHeader.from_bytes(inner_header),
            encrypted_payload = encrypted_payload,
        )

    ### Properties
    @property
    def encrypted_payload_length(self) -> int:
        """
        :return: Encrypted payload length.
        """
        return len(self.encrypted_payload)

    @property
    def length(self) -> int:
        """
        :return: Frame length.
        """
        return self.outer_header.SIZE + self.inner_header.SIZE + self.encrypted_payload_length

    ## Serialization properties
    @property
    def inner_header_raw_bytes(self) -> bytes:
        """
        :return: Current inner header bytes assembled from field values in wire order, without recomputing CRC.
        """
        return self.inner_header.raw_bytes

    @property
    def outer_header_raw_bytes(self) -> bytes:
        """
        :return: Current outer header bytes assembled from field values in wire order.
        """
        return self.outer_header.raw_bytes

    @property
    def raw_bytes(self) -> bytes:
        """
        :return: Current frame bytes assembled from field values in wire order, without recomputing CRC.
        """
        return b"".join((
            self.outer_header_raw_bytes,
            self.inner_header_raw_bytes,
            self.encrypted_payload,
        ))

    ## Validation properties
    @property
    def is_size_valid(self) -> bool:
        """True if the frame meets the minimum valid size."""
        total = len(self.outer_header_raw_bytes) + len(self.inner_header_raw_bytes) + len(self.encrypted_payload)
        return total >= self.MIN_SIZE

    @property
    def is_outer_magic_valid(self) -> bool:
        """True if outer magic bytes match 0x5053."""
        return self.outer_header.magic == self.OuterHeader.MAGIC

    @property
    def is_inner_magic_valid(self) -> bool:
        """True if inner magic bytes match 0x5050."""
        return self.inner_header.magic == self.InnerHeader.MAGIC

    @property
    def is_outer_padding_valid(self) -> bool:
        """True if outer padding bytes are 0x0000."""
        return self.outer_header.padding == bytes(2)

    @property
    def is_inner_frame_length_valid(self) -> bool:
        """True if inner_frame_length_inner matches the actual inner frame size."""
        actual = len(self.inner_header_raw_bytes) + len(self.encrypted_payload)
        return self.inner_header.inner_frame_length_int == actual

    @property
    def is_inner_frame_length_consistent(self) -> bool:
        """True if both headers declare the same inner frame length."""
        return self.outer_header.inner_frame_length_int == self.inner_header.inner_frame_length_int

    @property
    def is_crc_valid(self) -> bool:
        """True if the declared CRC matches the value calculated from current fields."""
        return self.inner_header.crc_int == self.calculate_crc()

    @property
    def is_valid(self) -> bool:
        """True if all validation checks pass."""
        return (
                self.is_size_valid
                and self.is_outer_magic_valid
                and self.is_inner_magic_valid
                and self.is_inner_frame_length_valid
                and self.is_inner_frame_length_consistent
                and self.is_crc_valid
        )

    ### To string
    def __str__(self) -> str:
        """Human-readable representation of all frame fields."""
        payload_hex = self.encrypted_payload.hex()
        # Truncate long payloads for readability
        if len(payload_hex) > 64:
            payload_hex = payload_hex[:64] + f"... ({len(self.encrypted_payload)} bytes)"

        return (
            f"Frame\n"
            f"  ## Outer Header ##\n"
            f"  magic                       {self.outer_header.magic.hex()}\n"
            f"  padding                     {self.outer_header.padding.hex()}\n"
            f"  inner_frame_length          {self.outer_header.inner_frame_length.hex():<12}  ({self.outer_header.inner_frame_length_int})\n"
            f"  response_inner_frame_length {self.outer_header.response_inner_frame_length.hex():<12}  ({self.outer_header.response_inner_frame_length_int})\n"
            f"  ## Inner Header ##\n"
            f"  magic                       {self.inner_header.magic.hex()}\n"
            f"  crc                         {self.inner_header.crc.hex():<12}  (0x{self.inner_header.crc_int:04X})\n"
            f"  operation                   {self.inner_header.operation.hex()} ({self.inner_header.operation_str})\n"
            f"  inner_frame_length          {self.inner_header.inner_frame_length.hex():<12}  ({self.inner_header.inner_frame_length_int})\n"
            f"  ## Encrypted Payload ({self.encrypted_payload_length} bytes) ##\n"
            f"  encrypted_payload           {payload_hex}\n"
        )

    ### Methods
    ## CRC
    def calculate_crc(self) -> int:
        """
        :return: Calculated CRC-16/ARC from current field values.
        """
        return _crc16_arc(
            self.inner_header_raw_bytes[self.InnerHeader.CRC_COVERAGE] + self.encrypted_payload
        )

    def update_crc(self) -> Self:
        """
        Updates the stored CRC bytes to match the value calculated from current fields.
        :return: Self with updated CRC-16/ARC from current fields.
        """
        self.inner_header.crc_int = self.calculate_crc()
        return self

    ## Validation
    def validate(self) -> None:
        """
        Validates the frame raising ValueError on the first failed check.
        :raises ValueError: If a checked property fails the check.
        """
        if not self.is_size_valid:
            raise ValueError(f"Frame too short: need ≥ {self.MIN_SIZE} bytes.")
        if not self.is_outer_magic_valid:
            raise ValueError(
                f"Outer magic mismatch: expected {self.OuterHeader.MAGIC.hex()}, "
                f"got {self.outer_header.magic.hex()}."
            )
        if not self.is_inner_magic_valid:
            raise ValueError(
                f"Inner magic mismatch: expected {self.InnerHeader.MAGIC.hex()}, "
                f"got {self.inner_header.magic.hex()}."
            )
        if not self.is_inner_frame_length_valid:
            actual = self.InnerHeader.SIZE + len(self.encrypted_payload)
            raise ValueError(
                f"Inner frame length mismatch: "
                f"declared {self.inner_header.inner_frame_length_int}, actual {actual}."
            )
        if not self.is_inner_frame_length_consistent:
            raise ValueError(
                f"Inner frame length inconsistency: "
                f"outer = {self.outer_header.inner_frame_length_int}, "
                f"inner = {self.inner_header.inner_frame_length_int}."
            )
        if not self.is_crc_valid:
            raise ValueError(
                f"CRC mismatch: declared 0x{self.inner_header.crc_int:04X}, "
                f"computed 0x{self.calculate_crc():04X}."
            )

    ## Serialization
    def to_bytes(self) -> bytes:
        """
        Recomputes CRC from current field values then assembles the complete wire frame as bytes.
        :return: Assembled frame bytes with updated CRC.
        """
        self.update_crc()
        return self.raw_bytes
