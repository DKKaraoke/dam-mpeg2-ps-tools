from bitstring import BitStream
from decimal import Decimal
from logging import getLogger
from typing import Literal

from .bitstream import copy

from .gop_index import GopIndexEntry, GopIndex
from .h264_annex_b import H264NalUnit
from .mpeg2_ps import (
    SYSTEM_CLOCK_FREQUENCY,
    Mpeg2PsProgramEnd,
    Mpeg2PesPacketType1,
    Mpeg2PesPacketType2,
    Mpeg2PsPackHeader,
    Mpeg2PsSystemHeader,
    Mpeg2PsSystemHeaderPStdInfo,
    Mpeg2AacAudioDescriptor,
    Mpeg2AvcVideoDescriptor,
    Mpeg2HevcVideoDescriptor,
    Mpeg2PsElementaryStreamMapEntry,
    Mpeg2PsProgramStreamMap,
    seek_packet,
    read_pes_packet,
)


DamMpeg2PsCodec = Literal["aac", "avc", "hevc"]


__GOP_INDEX_HEADER_SIZE = 6
__GOP_INDEX_ENTRY_SIZE = 12

__logger = getLogger(__name__)


def __size_of_gop_index_pes_packet_bytes(gop_index: GopIndex) -> int:
    """Calculate size of GOP Index PES Packet in bytes

    Args:
        gop_index (GopIndex): GOP Index

    Returns:
        int: Size of GOP Index PES Packet in bytes
    """

    # NAL unit prefix + NAL unit header + ...
    return 6 + __GOP_INDEX_HEADER_SIZE + len(gop_index.gops) * __GOP_INDEX_ENTRY_SIZE


def read_gop_index_pes_packet(stream: BitStream) -> GopIndex:
    """Read GOP Index

    Args:
        stream (BitStream): Input stream

    Raises:
        ValueError: GOP Index not found.
        ValueError: Invalid PES packet.

    Returns:
        GopIndex: GOP Index
    """

    packet_id = seek_packet(stream, 0xBF)
    if packet_id is None:
        raise ValueError("GOP Index not found.")
    pes_packet = read_pes_packet(stream)
    if pes_packet is None:
        raise ValueError("Invalid PES packet.")
    gop_index_stream = BitStream(pes_packet.PES_packet_data)
    return GopIndex.read(gop_index_stream)


def write_gop_index(
    input_stream: BitStream,
    output_stream: BitStream,
    gop_index: GopIndex,
) -> None:
    """Write GOP Index

    Args:
        input_stream (BitStream): Input stream
        output_stream (BitStream): Output stream
        gop_index (GopIndex): GOP Index

    Raises:
        ValueError: First Program Stream Map not found
        ValueError: Inavlid Program Stream Map
    """

    start_position = input_stream.bytepos

    # Seek and read first MPEG2-PS Program Stream Map
    packet_id = seek_packet(input_stream, 0xBC)
    if packet_id is None:
        raise ValueError("First Program Stream Map not found.")
    program_stream_map = Mpeg2PsProgramStreamMap.read(input_stream)
    if program_stream_map is None:
        raise ValueError("Inavlid Program Stream Map.")
    # Copy container header
    copy_size = input_stream.bytepos - start_position
    input_stream.bytepos = start_position
    copy(input_stream, output_stream, copy_size)

    pes_packet_size = __size_of_gop_index_pes_packet_bytes(gop_index)
    gops_offset = start_position + pes_packet_size
    # Adjust MPEG2-PS Pack Header position
    for gop in gop_index.gops:
        gop.ps_pack_header_position += gops_offset

    gop_index_buffer = gop_index.to_bytes()
    # Allow 0x000001 (Violation of standards), Do not emulation prevention
    Mpeg2PesPacketType2(0xBF, gop_index_buffer).write(output_stream)

    # Copy stream
    copy(input_stream, output_stream)


def write_container_header(stream: BitStream, codec: DamMpeg2PsCodec) -> None:
    """Write Container Header

    Args:
        stream (BitStream): Output stream
        codec (DamMpeg2PsCodec): Codec

    Raises:
        ValueError: Invalid argument `codec`
    """

    if codec == "aac":
        stream_type = 0x0F
        elementary_stream_info = [Mpeg2AacAudioDescriptor(0x00, 0x00, 0x00)]
    elif codec == "avc":
        stream_type = 0x1B
        elementary_stream_info = [
            Mpeg2AvcVideoDescriptor(
                77, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 40, 0x00, 0x00, 0x01
            )
        ]
    elif codec == "hevc":
        stream_type = 0x24
        elementary_stream_info = [
            Mpeg2HevcVideoDescriptor(
                0x00,
                0x00,
                0x00,
                0x00000000,
                0x00,
                0x00,
                0x00,
                0x00,
                0x000000000000,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            )
        ]
    else:
        raise ValueError("Argument `codec` must be DamMpeg2PsCodec.")

    Mpeg2PsPackHeader(0, 0, 20000, 0).write(stream)
    Mpeg2PsSystemHeader(
        50000, 0, 0, 0, 0, 1, 1, 1, [Mpeg2PsSystemHeaderPStdInfo(0xE0, 1, 3051)]
    ).write(stream)
    Mpeg2PsProgramStreamMap(
        0x01,
        0x01,
        [],
        [Mpeg2PsElementaryStreamMapEntry(stream_type, 0xE0, elementary_stream_info)],
    ).write(stream)


def write_mpeg2_ps(
    h264_es: list[H264NalUnit],
    output_stream: BitStream,
    codec: DamMpeg2PsCodec,
    frame_rate: Decimal,
) -> None:
    """Write MPEG2-PS

    Args:
        h264_es (list[H264NalUnit]): H.264-ES
        output_stream (bitstring.BitStream): Output stream for MPEG2-PS
        codec (DamMpeg2PsCodec): Codec
        frame_rate (Decimal): Frame rate
    """

    temp_stream = BitStream()

    # Write Container Header
    write_container_header(temp_stream, codec)

    # List Sequence and Access Unit
    nal_units = h264_es.copy()
    sequences: list[list[list[H264NalUnit]]] = []
    current_sequence: list[list[H264NalUnit]] = []
    current_access_unit: list[H264NalUnit] = []
    sps_detected = False
    while True:
        try:
            nal_unit = nal_units.pop(0)
        except IndexError:
            break

        # Access Unit Delimiter
        if nal_unit.nal_unit_type == 0x09:
            if sps_detected:
                if len(current_sequence) != 0:
                    sequences.append(current_sequence)
                    current_sequence = []
                sps_detected = False
            if len(current_access_unit) != 0:
                current_sequence.append(current_access_unit)
                current_access_unit = []

        # Sequence Parameter Set
        if nal_unit.nal_unit_type == 0x07:
            sps_detected = True

        current_access_unit.append(nal_unit)

    gops: list[GopIndexEntry] = []

    picture_count = Decimal(0)
    for sequence in sequences:
        access_unit_position = len(temp_stream) // 8

        # Write PS Pack header
        presentation_time = picture_count / frame_rate
        SCR_base = int((SYSTEM_CLOCK_FREQUENCY * presentation_time) / 300)
        SCR_ext = int((SYSTEM_CLOCK_FREQUENCY * presentation_time) % 300)
        ps_pack_header = Mpeg2PsPackHeader(SCR_base, SCR_ext, 20000, 0)
        ps_pack_header.write(temp_stream)

        for access_unit in sequence:
            presentation_time = picture_count / frame_rate
            pts = int((SYSTEM_CLOCK_FREQUENCY * presentation_time) / 300)
            dts = None

            access_unit_buffer = b""
            for nal_unit in access_unit:
                # Picture's NAL unit
                if nal_unit.nal_unit_type == 0x01 or nal_unit.nal_unit_type == 0x05:
                    picture_count += 1
                access_unit_buffer += nal_unit.to_bytes()

            # Fill and separate PES Packet
            pes_packet_data_buffer_length_limit: int
            if pts is None:
                PTS_DTS_flags = 0
                pes_packet_data_buffer_length_limit = 65535 - 3
            else:
                if dts is None:
                    PTS_DTS_flags = 2
                    pes_packet_data_buffer_length_limit = 65535 - 8
                else:
                    PTS_DTS_flags = 3
                    pes_packet_data_buffer_length_limit = 65535 - 13
            first_pes_packet_of_nal_unit = True
            while len(access_unit_buffer) != 0:
                if not first_pes_packet_of_nal_unit:
                    PTS_DTS_flags = 0
                    pes_packet_data_buffer_length_limit = 65535 - 3
                pes_packet_data_buffer = access_unit_buffer[
                    0:pes_packet_data_buffer_length_limit
                ]
                pes_packet = Mpeg2PesPacketType1(
                    0xE0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    PTS_DTS_flags,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    pts,
                    dts,
                    pes_packet_data_buffer,
                )
                pes_packet.write(temp_stream)
                access_unit_buffer = access_unit_buffer[
                    pes_packet_data_buffer_length_limit:
                ]
                first_pes_packet_of_nal_unit = False

        # Add a GOP index entry
        access_unit_size = len(temp_stream) // 8 - access_unit_position
        gops.append(GopIndexEntry(access_unit_position, access_unit_size, SCR_base))
        __logger.debug(
            f"GOP index entry added. access_unit_position={access_unit_position} access_unit_size={access_unit_size} pts={SCR_base} pts(msec)={SCR_base / 90}"
        )

    # Write Program End
    Mpeg2PsProgramEnd().write(temp_stream)
    # Add GOP index entry of Program end
    access_unit_position = len(temp_stream) // 8
    presentation_time = picture_count / frame_rate
    SCR_base = int((SYSTEM_CLOCK_FREQUENCY * presentation_time) / 300)
    gops.append(GopIndexEntry(access_unit_position, 0, SCR_base))
    __logger.debug(
        f"GOP index entry (Program End) added. access_unit_position={access_unit_position} access_unit_size=0 pts={SCR_base} pts(msec)={SCR_base / 90}"
    )

    # Write GOP index
    temp_stream.bytepos = 0
    write_gop_index(
        temp_stream, output_stream, GopIndex(0xFF, 0x01, 0xE0, 0x0, 0x0, gops)
    )
