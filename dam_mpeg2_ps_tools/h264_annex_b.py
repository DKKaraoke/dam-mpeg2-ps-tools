from dataclasses import dataclass
from io import BytesIO, BufferedReader
import os
import logging
from typing import Self

__logger = logging.getLogger(__name__)


def seek_nal_unit(
    stream: BufferedReader, nal_unit_type: int | None = None
) -> int | None:
    """Seek NAL Unit

    Args:
        stream (io.BufferedReader): Input stream
        nal_unit_type (int | None, optional): NAL Unit type. Defaults to None.

    Returns:
        int | None: NAL UNit type
    """

    zero_count = 0
    while True:
        buffer = stream.read(1)
        # End of stream
        if len(buffer) == 0:
            break
        current_byte = buffer[0]
        if 2 <= zero_count and current_byte == 0x01:
            buffer = stream.read(1)
            # End of stream
            if len(buffer) == 0:
                break
            current_byte = buffer[0]
            current_nal_unit_type = current_byte & 0x1F
            zero_count = min(zero_count, 3)
            if nal_unit_type is None:
                stream.seek(-(zero_count + 2), os.SEEK_CUR)
                return current_nal_unit_type
            else:
                if current_nal_unit_type == nal_unit_type:
                    stream.seek(-(zero_count + 2), os.SEEK_CUR)
                    return current_nal_unit_type
        # Count zero
        if current_byte == 0x00:
            zero_count += 1
        else:
            zero_count = 0


def index_nal_unit(stream: BufferedReader) -> list[tuple[int, int]]:
    """Index NAL Unit

    Args:
        stream (io.BufferedReader): Input stream

    Returns:
        list[tuple[int, int]]: List of position and length
    """

    index: list[tuple[int, int]] = []

    last_position = -1
    while True:
        nal_unit_type = seek_nal_unit(stream)
        if nal_unit_type is None:
            break
        position = stream.tell()
        if last_position != -1:
            index.append((last_position, position - last_position))
        last_position = position
        stream.seek(4, os.SEEK_CUR)

    if last_position != -1:
        position = stream.tell()
        index.append((last_position, position - last_position))

    return index


@dataclass
class H264NalUnit:
    """H.264 NAL Unit"""

    __EBSP_ESCAPE_START_CODE = b"\x00\x00\x03"
    __NAL_UNIT_START_CODE = b"\x00\x00\x01"
    __NAL_UNIT_START_CODE_LONG = b"\x00\x00\x00\x01"

    is_start_code_long: bool
    nal_ref_idc: int
    nal_unit_type: int
    rbsp: bytes

    @staticmethod
    def __find_ebsp_escaped_position(buffer: bytes, start: int = 0) -> int:
        """Find EBSP escaped position

        Args:
            buffer (bytes): Input buffer
            start (int, optional): Start position. Defaults to 0.

        Returns:
            int: Found position
        """

        position = buffer.find(H264NalUnit.__EBSP_ESCAPE_START_CODE, start)
        if position == -1 or len(buffer) - 1 < position + 3:
            return -1
        if 0x03 < buffer[position + 3]:
            return H264NalUnit.__find_ebsp_escaped_position(buffer, position + 4)
        return position

    @staticmethod
    def __list_ebsp_escaped_position(buffer: bytes) -> list[int]:
        """List EBSP escaped position

        Args:
            buffer (bytes): Input buffer

        Returns:
            list[int]: List of EBSP escaped position
        """

        position_list: list[int] = []
        position = 0
        while True:
            position = H264NalUnit.__find_ebsp_escaped_position(buffer, position)
            if position == -1:
                break
            position_list.append(position)
            position += 4
        return position_list

    @staticmethod
    def __ebsp_unescape(buffer: bytes) -> bytes:
        """EBSP unescape

        Args:
            buffer (bytes): Input buffer

        Returns:
            bytes: Unescaped data
        """
        return b"\x00\x00" + buffer[3:4]

    @staticmethod
    def __ebsp_to_rbsp(ebsp: bytes) -> bytes:
        """EPSB to RBSP

        Args:
            ebsp (bytes): EBSP

        Returns:
            bytes: RBSP
        """

        rbsp = b""
        escaped_positions = H264NalUnit.__list_ebsp_escaped_position(ebsp)
        current_position = 0
        for escaped_position in escaped_positions:
            rbsp += ebsp[current_position:escaped_position]
            rbsp += H264NalUnit.__ebsp_unescape(
                ebsp[escaped_position : escaped_position + 4]
            )
            current_position = escaped_position + 4
        rbsp += ebsp[current_position:]
        return rbsp

    @staticmethod
    def __find_ebsp_escape_needed_position(buffer: bytes, start=0) -> int:
        """Find EBSP escape needed position

        Args:
            buffer (bytes): Input buffer
            start (int, optional): Start position. Defaults to 0.

        Returns:
            int: Found position
        """

        position = buffer.find(b"\x00\x00", start)
        buffer_length = len(buffer)
        if position == -1 or buffer_length - 1 < position + 2:
            return -1
        tail_value = buffer[position + 2]
        if 0x03 < tail_value:
            return H264NalUnit.__find_ebsp_escape_needed_position(buffer, position + 3)
        # Do not escape tail 0x000003
        if buffer_length - 1 == position + 2 and tail_value == 0x03:
            return -1
        return position

    @staticmethod
    def __list_ebsp_escape_needed_position(buffer: bytes):
        """List EBSP escape needed position

        Args:
            buffer (bytes): Input buffer

        Returns:
            _type_: List of EBSP escape needed position
        """

        position_list: list[int] = []
        position = 0
        while True:
            position = H264NalUnit.__find_ebsp_escape_needed_position(buffer, position)
            if position == -1:
                break
            position_list.append(position)
            position += 3
        return position_list

    @staticmethod
    def __ebsp_escape(buffer: bytes) -> bytes:
        """EBSP escape

        Args:
            buffer (bytes): Input buffer

        Returns:
            bytes: Escaped data
        """

        return H264NalUnit.__EBSP_ESCAPE_START_CODE + buffer[2:3]

    @staticmethod
    def __rbsp_to_ebsp(rbsp: bytes) -> bytes:
        """RBSP to EBSP

        Args:
            rbsp (bytes): RBSP

        Returns:
            bytes: EBSP
        """

        ebsp = b""
        escape_needed_positions = H264NalUnit.__list_ebsp_escape_needed_position(rbsp)
        current_position = 0
        for escape_needed_position in escape_needed_positions:
            ebsp += rbsp[current_position:escape_needed_position]
            ebsp += H264NalUnit.__ebsp_escape(
                rbsp[escape_needed_position : escape_needed_position + 3]
            )
            current_position = escape_needed_position + 3
        ebsp += rbsp[current_position:]
        return ebsp

    @classmethod
    def from_bytes(cls, buffer: bytes) -> Self:
        """NAL Unit from bytes

        Args:
            buffer (bytes): Input buffer

        Raises:
            ValueError: Invalid argument `buffer` length.
            ValueError: Invalid `header_buffer` length.
            ValueError: Invalid `forbidden_zero_bit`.

        Returns:
            H264NalUnit: NAL Unit
        """

        if len(buffer) < 4:
            raise ValueError("Invalid argument `buffer` length.")

        stream = BytesIO(buffer)

        # Prefix
        prefix_zero_count = 0
        for _ in range(4):
            buffer = stream.read(1)
            if len(buffer) == 1 and buffer[0] == 0x01:
                break
            prefix_zero_count += 1
        is_start_code_long = False if prefix_zero_count <= 2 else True
        # Read header
        header_buffer = stream.read(1)
        if len(header_buffer) != 1:
            raise ValueError("Invalid `header_buffer` length.")
        header = header_buffer[0]
        forbidden_zero_bit = header >> 7
        if forbidden_zero_bit != 0x00:
            raise ValueError("Invalid `forbidden_zero_bit`.")
        nal_ref_idc = (header >> 5) & 0x03
        nal_unit_type = header & 0x1F
        # Read EBSP
        ebsp = stream.read()
        rbsp = H264NalUnit.__ebsp_to_rbsp(ebsp)

        return cls(is_start_code_long, nal_ref_idc, nal_unit_type, rbsp)

    def to_bytes(self) -> bytes:
        """To bytes

        Returns:
            bytes: This instance as bytes
        """

        prefix = (
            H264NalUnit.__NAL_UNIT_START_CODE_LONG
            if self.is_start_code_long
            else H264NalUnit.__NAL_UNIT_START_CODE
        )

        header = (self.nal_ref_idc & 0x03) << 5
        header |= self.nal_unit_type & 0x1F

        ebsp = H264NalUnit.__rbsp_to_ebsp(self.rbsp)

        return prefix + header.to_bytes(length=1, byteorder="big") + ebsp
