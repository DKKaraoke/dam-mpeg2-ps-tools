from abc import ABC, abstractmethod
from bitstring import BitArray, BitStream, ReadError, pack
from dataclasses import dataclass
from logging import getLogger
from typing import Self, Union


SYSTEM_CLOCK_FREQUENCY = 27000000
PACKET_START_CODE = b"\x00\x00\x01"

__logger = getLogger(__name__)


@dataclass
class Mpeg2PsProgramEnd:
    """PS Program End"""

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `packet_start_code_prefix`
            ValueError: Invalid `stream_i`

        Returns:
            Self: PS Program Stream Map
        """

        packet_start_code_prefix: bytes = stream.read("bytes:3")
        if packet_start_code_prefix != PACKET_START_CODE:
            raise ValueError("Invalid `packet_start_code_prefix`.")
        stream_id: int = stream.read("uint:8")
        if stream_id != 0xB9:
            raise ValueError("Invalid `stream_id`.")

    def write(self, stream: BitStream) -> None:
        stream.append(PACKET_START_CODE + b"\xb9")


class Mpeg2PesPacketBase(ABC):
    """PES Packet Base Class"""

    @staticmethod
    def _read_common(stream: BitStream) -> tuple[int, bytes]:
        """Read Common Part

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `packet_start_code_prefix`

        Returns:
            tuple[int, bytes]: Stream ID and Payload
        """

        packet_start_code_prefix: bytes = stream.read("bytes:3")
        if packet_start_code_prefix != PACKET_START_CODE:
            raise ValueError("Invalid `packet_start_code_prefix`.")
        stream_id: int = stream.read("uint:8")
        PES_packet_length: int = stream.read("uintbe:16")
        payload = stream.read(8 * PES_packet_length)
        return stream_id, payload

    @staticmethod
    def peek_stream_id(stream: BitStream) -> int:
        """Peek Stream ID

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `packet_start_code_prefix`

        Returns:
            int: Stream ID
        """

        buffer: bytes = stream.peek("bytes:4")
        if buffer[0:3] != PACKET_START_CODE:
            raise ValueError("Invalid `packet_start_code_prefix`.")
        return buffer[3]

    def __init__(self, stream_id: int) -> None:
        """Constructor

        Args:
            stream_id (int): Stream ID
        """

        self.stream_id = stream_id

    @abstractmethod
    def _write_payload(self, stream: BitStream) -> None:
        """Write payload

        Args:
            stream (BitStream): Output stream
        """

        pass

    def payload_to_bytes(self) -> bytes:
        """Payload to bytes

        Returns:
            bytes: Payload as bytes
        """

        stream = BitStream()
        self._write_payload(stream)
        return stream.tobytes()

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        payload_buffer = self.payload_to_bytes()
        stream.append(PACKET_START_CODE)
        stream.append(pack("uint:8", self.stream_id))
        stream.append(pack("uintbe:16", len(payload_buffer)))
        stream.append(payload_buffer)


@dataclass
class Mpeg2PesPacketType1(Mpeg2PesPacketBase):
    stream_id: int
    PES_scrambling_control: int
    PES_priority: int
    data_alignment_indicator: int
    copyright: int
    original_or_copy: int
    PTS_DTS_flags: int
    ESCR_flag: int
    ES_rate_flag: int
    DSM_trick_mode_flag: int
    additional_copy_info_flag: int
    PES_CRC_flag: int
    PES_extension_flag: int
    pts: int
    dts: int
    PES_packet_data: bytes

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Returns:
            Self: PES Packet Type-1
        """

        stream_id, payload = Mpeg2PesPacketBase._read_common(stream)
        payload_stream = BitStream(payload)
        # Skip '10'
        payload_stream.pos += 2
        PES_scrambling_control: int = payload_stream.read("uint:2")
        PES_priority: int = payload_stream.read("uint:1")
        data_alignment_indicator: int = payload_stream.read("uint:1")
        copyright: int = payload_stream.read("uint:1")
        original_or_copy: int = payload_stream.read("uint:1")
        PTS_DTS_flags: int = payload_stream.read("uint:2")
        ESCR_flag: int = payload_stream.read("uint:1")
        ES_rate_flag: int = payload_stream.read("uint:1")
        DSM_trick_mode_flag: int = payload_stream.read("uint:1")
        additional_copy_info_flag: int = payload_stream.read("uint:1")
        PES_CRC_flag: int = payload_stream.read("uint:1")
        PES_extension_flag: int = payload_stream.read("uint:1")
        PES_header_data_length: int = payload_stream.read("uint:8")
        PES_header_data_stream: int = BitStream(
            payload_stream.read(8 * PES_header_data_length)
        )
        pts: int | None = None
        dts: int | None = None
        if PTS_DTS_flags == 0x02:
            raw_PTS: int = PES_header_data_stream.read("uintbe:40")
            pts = (raw_PTS >> 3) & (0x0007 << 30)
            pts |= (raw_PTS >> 2) & (0x7FFF << 15)
            pts |= (raw_PTS >> 1) & 0x7FFF
        if PTS_DTS_flags == 0x03:
            raw_PTS: int = PES_header_data_stream.read("uintbe:40")
            pts = (raw_PTS >> 3) & (0x0007 << 30)
            pts |= (raw_PTS >> 2) & (0x7FFF << 15)
            pts |= (raw_PTS >> 1) & 0x7FFF
            raw_DTS: int = PES_header_data_stream.read("uintbe:40")
            dts = (raw_DTS >> 3) & (0x0007 << 30)
            dts |= (raw_DTS >> 2) & (0x7FFF << 15)
            dts |= (raw_DTS >> 1) & 0x7FFF
        PES_packet_data: bytes = payload_stream.read("bytes")
        return cls(
            stream_id,
            PES_scrambling_control,
            PES_priority,
            data_alignment_indicator,
            copyright,
            original_or_copy,
            PTS_DTS_flags,
            ESCR_flag,
            ES_rate_flag,
            DSM_trick_mode_flag,
            additional_copy_info_flag,
            PES_CRC_flag,
            PES_extension_flag,
            pts,
            dts,
            PES_packet_data,
        )

    def _write_payload(self, stream: BitStream) -> None:
        stream.append(BitArray(bin="10"))
        stream.append(pack("uint:2", self.PES_scrambling_control))
        stream.append(pack("uint:1", self.PES_priority))
        stream.append(pack("uint:1", self.data_alignment_indicator))
        stream.append(pack("uint:1", self.copyright))
        stream.append(pack("uint:1", self.original_or_copy))
        stream.append(pack("uint:2", self.PTS_DTS_flags))
        stream.append(pack("uint:1", self.ESCR_flag))
        stream.append(pack("uint:1", self.ES_rate_flag))
        stream.append(pack("uint:1", self.DSM_trick_mode_flag))
        stream.append(pack("uint:1", self.additional_copy_info_flag))
        stream.append(pack("uint:1", self.PES_CRC_flag))
        stream.append(pack("uint:1", self.PES_extension_flag))

        PES_header_data_stream = BitStream()
        if self.PTS_DTS_flags == 0x02:
            raw_PTS = 0x2100010001
            raw_PTS |= (self.pts & (0x0007 << 30)) << 3
            raw_PTS |= (self.pts & (0x7FFF << 15)) << 2
            raw_PTS |= (self.pts & 0x7FFF) << 1
            PES_header_data_stream.append(pack("uintbe:40", raw_PTS))
        elif self.PTS_DTS_flags == 0x03:
            raw_PTS = 0x3100010001
            raw_PTS |= (self.pts & (0x0007 << 30)) << 3
            raw_PTS |= (self.pts & (0x7FFF << 15)) << 2
            raw_PTS |= (self.pts & 0x7FFF) << 1
            PES_header_data_stream.append(pack("uintbe:40", raw_PTS))
            raw_DTS = 0x1100010001
            raw_DTS |= (self.dts & (0x0007 << 30)) << 3
            raw_DTS |= (self.dts & (0x7FFF << 15)) << 2
            raw_DTS |= (self.dts & 0x7FFF) << 1
            PES_header_data_stream.append(pack("uintbe:40", raw_DTS))
        PES_header_data_buffer = PES_header_data_stream.tobytes()
        stream.append(pack("uint:8", len(PES_header_data_buffer)))
        stream.append(PES_header_data_buffer)

        stream.append(self.PES_packet_data)


@dataclass
class Mpeg2PesPacketType2(Mpeg2PesPacketBase):
    stream_id: int
    PES_packet_data: bytes

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Returns:
            Self: PES Packet Type-2
        """

        stream_id, payload = Mpeg2PesPacketBase._read_common(stream)
        return cls(stream_id, payload)

    def _write_payload(self, stream: BitStream) -> None:
        stream.append(self.PES_packet_data)


@dataclass
class Mpeg2PesPacketType3(Mpeg2PesPacketBase):
    stream_id: int
    PES_packet_length: int

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Returns:
            Self: PES Packet Type-3
        """

        stream_id, payload = Mpeg2PesPacketBase._read_common(stream)
        return cls(stream_id, len(payload))

    def _write_payload(self, stream: BitStream) -> None:
        for _ in range(self.PES_packet_length):
            stream.append(b"\xff")


Mpeg2PesPacket = Union[Mpeg2PesPacketType1, Mpeg2PesPacketType2, Mpeg2PesPacketType3]


def read_pes_packet(stream: BitStream) -> Mpeg2PesPacket:
    """Read PES Packet

    Args:
        stream (BitStream): Input stream

    Raises:
        ValueError: Invalid `packet_start_code_prefix`
        ValueError: Unknown Stream ID detected

    Returns:
        Mpeg2PesPacket: PES Packet
    """

    stream_id = Mpeg2PesPacketBase.peek_stream_id(stream)
    if (
        stream_id != 0xBC  # program_stream_map
        and stream_id != 0xBE  # padding_stream
        and stream_id != 0xBF  # private_stream_2
        and stream_id != 0xF0  # ECM
        and stream_id != 0xF1  # EMM
        and stream_id != 0xFF  # program_stream_directory
        and stream_id != 0xF2  # DSMCC_stream
        and stream_id != 0xF8  # ITU-T Rec. H.222.1 type E stream
    ):
        return Mpeg2PesPacketType1.read(stream)
    elif (
        stream_id == 0xBC  # program_stream_map
        or stream_id == 0xBF  # private_stream_2
        or stream_id == 0xF0  # ECM
        or stream_id == 0xF1  # EMM
        or stream_id == 0xFF  # program_stream_directory
        or stream_id == 0xF2  # DSMCC_stream
        or stream_id == 0xF8  # ITU-T Rec. H.222.1 type E stream
    ):
        return Mpeg2PesPacketType2.read(stream)
    elif stream_id == 0xBE:  # padding_stream
        return Mpeg2PesPacketType3.read(stream)
    else:
        raise ValueError("Unknown Stream ID detected.")


@dataclass
class Mpeg2PsPackHeader:
    system_clock_reference_base: int
    system_clock_reference_extension: int
    program_mux_rate: int
    pack_stuffing_length: int

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `pack_start_code`

        Returns:
            Self: PS Pack Header
        """

        pack_start_code: bytes = stream.read("bytes:4")
        if pack_start_code != (PACKET_START_CODE + b"\xba"):
            raise ValueError("Invalid `pack_start_code`.")
        system_clock_reference_raw: int = stream.read("uintbe:48")
        system_clock_reference_base = (system_clock_reference_raw >> 13) & (0x03 << 30)
        system_clock_reference_base |= (system_clock_reference_raw >> 12) & (
            0x7FFF << 15
        )
        system_clock_reference_base |= (system_clock_reference_raw >> 11) & 0x7FFF
        system_clock_reference_extension = (system_clock_reference_raw >> 1) & 0x01FF
        program_mux_rate: int = stream.read("uintbe:24") >> 2
        # Skip marker_bits and Reserved
        stream.pos += 5
        pack_stuffing_length: int = stream.read("uint:3")
        return cls(
            system_clock_reference_base,
            system_clock_reference_extension,
            program_mux_rate,
            pack_stuffing_length,
        )

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        stream.append(PACKET_START_CODE + b"\xba")
        system_clock_reference_raw = 0x440004000401
        system_clock_reference_raw |= (
            self.system_clock_reference_base & (0x03 << 30)
        ) << 13
        system_clock_reference_raw |= (
            self.system_clock_reference_base & (0x7FFF << 15)
        ) << 12
        system_clock_reference_raw |= (self.system_clock_reference_base & 0x7FFF) << 11
        system_clock_reference_raw |= (
            self.system_clock_reference_extension & 0x01FF
        ) << 1
        stream.append(pack("uintbe:48", system_clock_reference_raw))
        program_mux_rate_raw = 0x000003
        program_mux_rate_raw |= (self.program_mux_rate & 0x3FFFFF) << 2
        stream.append(pack("uintbe:24", program_mux_rate_raw))
        pack_stuffing_length_raw = 0xF8
        pack_stuffing_length_raw |= self.pack_stuffing_length & 0x03
        stream.append(pack("uint:8", pack_stuffing_length_raw))
        for _ in range(self.pack_stuffing_length):
            stream.append(b"\0xff")


@dataclass
class Mpeg2PsSystemHeaderPStdInfo:
    stream_id: int
    P_STD_buffer_bound_scale: int
    P_STD_buffer_size_bound: int


@dataclass
class Mpeg2PsSystemHeader:
    rate_bound: int
    audio_bound: int
    fixed_flag: int
    CSPS_flag: int
    system_audio_lock_flag: int
    system_video_lock_flag: int
    video_bound: int
    packet_rate_restriction_flag: int
    P_STD_info: list[Mpeg2PsSystemHeaderPStdInfo]

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `system_header_start_code`

        Returns:
            Mpeg2PsSystemHeader: PS System Header
        """

        system_header_start_code: bytes = stream.read("bytes:4")
        if system_header_start_code != (PACKET_START_CODE + b"\xbb"):
            raise ValueError("Invalid `system_header_start_code`.")
        header_length: int = stream.read("uintbe:16")
        header_stream = BitStream(stream.read(8 * header_length))

        rate_bound: int = (header_stream.read("uintbe:24") >> 1) & 0x3FFFFF
        audio_bound: int = header_stream.read("uint:6")
        fixed_flag: int = header_stream.read("uint:1")
        CSPS_flag: int = header_stream.read("uint:1")
        system_audio_lock_flag: int = header_stream.read("uint:1")
        system_video_lock_flag: int = header_stream.read("uint:1")
        # Skip marker_bit
        header_stream.pos += 1
        video_bound: int = header_stream.read("uint:5")
        packet_rate_restriction_flag: int = header_stream.read("uint:1")
        # Skip reserved_bits
        header_stream.pos += 7

        P_STD_info: list[Mpeg2PsSystemHeaderPStdInfo] = []
        while True:
            stream_id: int
            try:
                stream_id = header_stream.read("uint:8")
            except ReadError:
                # End of Stream
                break
            if stream_id & 0x80 != 0x80:
                # P-STD info not found
                header_stream.pos -= 8
                break
            temp: int = header_stream.read("uintbe:16")
            P_STD_buffer_bound_scale = (temp >> 13) & 0x01
            P_STD_buffer_size_bound = temp & 0x1FFF
            P_STD_info.append(
                Mpeg2PsSystemHeaderPStdInfo(
                    stream_id, P_STD_buffer_bound_scale, P_STD_buffer_size_bound
                )
            )

        return cls(
            rate_bound,
            audio_bound,
            fixed_flag,
            CSPS_flag,
            system_audio_lock_flag,
            system_video_lock_flag,
            video_bound,
            packet_rate_restriction_flag,
            P_STD_info,
        )

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        stream.append(PACKET_START_CODE + b"\xbb")

        header_stream = BitStream()
        header_stream.append(
            pack("uintbe:24", 0x800001 | ((self.rate_bound & 0x3FFFFF) << 1))
        )
        header_stream.append(pack("uint:6", self.audio_bound))
        header_stream.append(pack("uint:1", self.fixed_flag))
        header_stream.append(pack("uint:1", self.CSPS_flag))
        header_stream.append(pack("uint:1", self.system_audio_lock_flag))
        header_stream.append(pack("uint:1", self.system_video_lock_flag))
        # marker_bit
        header_stream.append(pack("uint:1", 1))
        header_stream.append(pack("uint:5", self.video_bound))
        header_stream.append(pack("uint:1", self.packet_rate_restriction_flag))
        # reserved_bits
        header_stream.append(BitArray(bin="1111111"))
        for P_STD_info_entry in self.P_STD_info:
            header_stream.append(pack("uint:8", P_STD_info_entry.stream_id))
            temp = 0xC000
            temp |= (P_STD_info_entry.P_STD_buffer_bound_scale & 0x01) << 13
            temp |= P_STD_info_entry.P_STD_buffer_size_bound & 0x1FFF
            header_stream.append(pack("uintbe:16", temp))

        header_bytes = header_stream.tobytes()
        stream.append(pack("uintbe:16", len(header_bytes)))
        stream.append(header_bytes)


@dataclass
class Mpeg2GenericDescriptor:
    descriptor_tag: int
    data: bytes

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read
        Args:
            stream (BitStream): Input stream

        Returns:
            Self: Generic Descriptor
        """

        descriptor_tag = stream.read("uint:8")
        descriptor_length = stream.read("uint:8")
        data_buffer: bytes = stream.read(8 * descriptor_length).bytes
        return cls(descriptor_tag, data_buffer)

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        stream.append(pack("uint:8", self.descriptor_tag))
        stream.append(pack("uint:8", len(self.data)))
        stream.append(self.data)


@dataclass
class Mpeg2AvcVideoDescriptor:
    profile_idc: int
    constraint_set0_flag: int
    constraint_set1_flag: int
    constraint_set2_flag: int
    constraint_set3_flag: int
    constraint_set4_flag: int
    constraint_set5_flag: int
    AVC_compatible_flags: int
    level_idc: int
    AVC_still_present: int
    AVC_24_hour_picture_flag: int
    Frame_Packing_SEI_not_present_flag: int

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `descriptor_tag`

        Returns:
            Self: AVC Video Descriptor
        """

        descriptor_tag: int = stream.read("uint:8")
        if descriptor_tag != 0x28:
            raise ValueError("Invalid `descriptor_tag`.")
        descriptor_length: int = stream.read("uint:8")
        data_stream = BitStream(stream.read(8 * descriptor_length))
        profile_idc: int = data_stream.read("uint:8")
        constraint_set0_flag: int = data_stream.read("uint:1")
        constraint_set1_flag: int = data_stream.read("uint:1")
        constraint_set2_flag: int = data_stream.read("uint:1")
        constraint_set3_flag: int = data_stream.read("uint:1")
        constraint_set4_flag: int = data_stream.read("uint:1")
        constraint_set5_flag: int = data_stream.read("uint:1")
        AVC_compatible_flags: int = data_stream.read("uint:2")
        level_idc: int = data_stream.read("uint:8")
        AVC_still_present: int = data_stream.read("uint:1")
        AVC_24_hour_picture_flag: int = data_stream.read("uint:1")
        Frame_Packing_SEI_not_present_flag: int = data_stream.read("uint:1")
        # Skip reserved
        data_stream.pos += 5
        return cls(
            profile_idc,
            constraint_set0_flag,
            constraint_set1_flag,
            constraint_set2_flag,
            constraint_set3_flag,
            constraint_set4_flag,
            constraint_set5_flag,
            AVC_compatible_flags,
            level_idc,
            AVC_still_present,
            AVC_24_hour_picture_flag,
            Frame_Packing_SEI_not_present_flag,
        )

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        stream.append(b"\x28\x04")
        stream.append(pack("uint:8", self.profile_idc))
        stream.append(pack("uint:1", self.constraint_set0_flag))
        stream.append(pack("uint:1", self.constraint_set1_flag))
        stream.append(pack("uint:1", self.constraint_set2_flag))
        stream.append(pack("uint:1", self.constraint_set3_flag))
        stream.append(pack("uint:1", self.constraint_set4_flag))
        stream.append(pack("uint:1", self.constraint_set5_flag))
        stream.append(pack("uint:2", self.AVC_compatible_flags))
        stream.append(pack("uint:8", self.level_idc))
        stream.append(pack("uint:1", self.AVC_still_present))
        stream.append(pack("uint:1", self.AVC_24_hour_picture_flag))
        stream.append(pack("uint:1", self.Frame_Packing_SEI_not_present_flag))
        # reserved
        stream.append(BitArray(bin="11111"))


@dataclass
class Mpeg2AacAudioDescriptor:
    MPEG_2_AAC_profile: int
    MPEG_2_AAC_channel_configuration: int
    MPEG_2_AAC_additional_information: int

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `descriptor_tag`

        Returns:
            Self: AAC Audio Descriptor
        """

        descriptor_tag: int = stream.read("uint:8")
        if descriptor_tag != 0x2B:
            raise ValueError("Invalid `descriptor_tag`.")
        descriptor_length: int = stream.read("uint:8")
        data_stream = BitStream(stream.read(8 * descriptor_length))
        MPEG_2_AAC_profile: int = data_stream.read("uint:8")
        MPEG_2_AAC_channel_configuration: int = data_stream.read("uint:8")
        MPEG_2_AAC_additional_information: int = data_stream.read("uint:8")
        return cls(
            MPEG_2_AAC_profile,
            MPEG_2_AAC_channel_configuration,
            MPEG_2_AAC_additional_information,
        )

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        stream.append(b"\x2b\x03")
        stream.append(pack("uint:8", self.MPEG_2_AAC_profile))
        stream.append(pack("uint:8", self.MPEG_2_AAC_channel_configuration))
        stream.append(pack("uint:8", self.MPEG_2_AAC_additional_information))


@dataclass
class Mpeg2HevcVideoDescriptor:
    profile_space: int
    tier_flag: int
    profile_idc: int
    profile_compatibility_indication: int
    progressive_source_flag: int
    interlaced_source_flag: int
    non_packed_constraint_flag: int
    frame_only_constraint_flag: int
    copied_44bits: int
    level_idc: int
    temporal_layer_subset_flag: int
    HEVC_still_present_flag: int
    HEVC_24hr_picture_present_flag: int
    sub_pic_hrd_params_not_present_flag: int
    HDR_WCG_idc: int
    # Optional fields
    temporal_id_min: int
    temporal_id_max: int

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `descriptor_tag`

        Returns:
            Self: HEVC Video Descriptor
        """

        descriptor_tag: int = stream.read("uint:8")
        if descriptor_tag != 0x38:
            raise ValueError("Invalid `descriptor_tag`.")
        descriptor_length: int = stream.read("uint:8")
        data_stream = BitStream(stream.read(8 * descriptor_length))
        profile_space: int = data_stream.read("uint:2")
        tier_flag: int = data_stream.read("uint:1")
        profile_idc: int = data_stream.read("uint:5")
        profile_compatibility_indication: int = data_stream.read("uintbe:32")
        progressive_source_flag: int = data_stream.read("uint:1")
        interlaced_source_flag: int = data_stream.read("uint:1")
        non_packed_constraint_flag: int = data_stream.read("uint:1")
        frame_only_constraint_flag: int = data_stream.read("uint:1")
        copied_44bits: int = data_stream.read("uintbe:44")
        level_idc: int = data_stream.read("uint:8")
        temporal_layer_subset_flag: int = data_stream.read("uint:1")
        HEVC_still_present_flag: int = data_stream.read("uint:1")
        HEVC_24hr_picture_present_flag: int = data_stream.read("uint:1")
        sub_pic_hrd_params_not_present_flag: int = data_stream.read("uint:1")
        # Skip reserved
        data_stream.pos += 2
        HDR_WCG_idc: int = data_stream.read("uint:2")
        temporal_id_min: int | None = None
        temporal_id_max: int | None = None
        if temporal_layer_subset_flag == 0x01:
            temporal_id_min: int = data_stream.read("uint:3")
            # Skip reserved
            data_stream.pos += 5
            temporal_id_max: int = data_stream.read("uint:3")
            # Skip reserved
            data_stream.pos += 5
        return cls(
            profile_space,
            tier_flag,
            profile_idc,
            profile_compatibility_indication,
            progressive_source_flag,
            interlaced_source_flag,
            non_packed_constraint_flag,
            frame_only_constraint_flag,
            copied_44bits,
            level_idc,
            temporal_layer_subset_flag,
            HEVC_still_present_flag,
            HEVC_24hr_picture_present_flag,
            sub_pic_hrd_params_not_present_flag,
            HDR_WCG_idc,
            temporal_id_min,
            temporal_id_max,
        )

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        stream.append(b"\x2b")
        if self.temporal_layer_subset_flag & 0x01 == 0x01:
            stream.append(b"\x0f")
        else:
            stream.append(b"\x0d")
        stream.append(pack("uint:2", self.profile_space))
        stream.append(pack("uint:1", self.tier_flag))
        stream.append(pack("uint:5", self.profile_idc))
        stream.append(pack("uintbe:32", self.profile_compatibility_indication))
        stream.append(pack("uint:1", self.progressive_source_flag))
        stream.append(pack("uint:1", self.interlaced_source_flag))
        stream.append(pack("uint:1", self.non_packed_constraint_flag))
        stream.append(pack("uint:1", self.frame_only_constraint_flag))
        stream.append(pack("uintbe:44", self.copied_44bits))
        stream.append(pack("uint:8", self.level_idc))
        stream.append(pack("uint:1", self.temporal_layer_subset_flag))
        stream.append(pack("uint:1", self.HEVC_still_present_flag))
        stream.append(pack("uint:1", self.HEVC_24hr_picture_present_flag))
        stream.append(pack("uint:1", self.sub_pic_hrd_params_not_present_flag))
        # reserved
        stream.append(BitArray(bin="11"))
        stream.append(pack("uint:2", self.HDR_WCG_idc))
        if self.temporal_layer_subset_flag & 0x01 == 0x01:
            stream.append(pack("uint:3", self.temporal_id_min))
            # reserved
            stream.append(BitArray(bin="11111"))
            stream.append(pack("uint:3", self.temporal_id_max))
            # reserved
            stream.append(BitArray(bin="11111"))


Mpeg2Descriptor = Union[
    Mpeg2GenericDescriptor,
    Mpeg2AvcVideoDescriptor,
    Mpeg2AacAudioDescriptor,
    Mpeg2HevcVideoDescriptor,
]


def read_descriptor(stream: BitStream) -> Mpeg2Descriptor | None:
    """Read Descriptor

    Args:
        stream (BitStream): Input stream

    Returns:
        Mpeg2Descriptor | None: Descriptor or None (Reached to End of Stream)
    """

    descriptor_tag: int
    try:
        descriptor_tag = stream.peek("uint:8")
    except ReadError:
        # End of Stream
        return
    if descriptor_tag == 0x28:
        return Mpeg2AvcVideoDescriptor.read(stream)
    elif descriptor_tag == 0x2B:
        return Mpeg2AacAudioDescriptor.read(stream)
    elif descriptor_tag == 0x38:
        return Mpeg2HevcVideoDescriptor.read(stream)
    else:
        return Mpeg2GenericDescriptor.read(stream)


@dataclass
class Mpeg2PsElementaryStreamMapEntry:
    stream_type: int
    elementary_stream_id: int
    elementary_stream_info: list[Mpeg2Descriptor]


@dataclass
class Mpeg2PsProgramStreamMap:
    current_next_indicator: int
    program_stream_map_version: int
    program_stream_info: list[Mpeg2Descriptor]
    elementary_stream_map: list[Mpeg2PsElementaryStreamMapEntry]

    @staticmethod
    def __crc32(message: bytes) -> int:
        """Calculate CRC-32

        Args:
            message (bytes): Message

        Returns:
            int: CRC-32 Value
        """

        crc = 0xFFFFFFFF
        for value in message:
            crc ^= value << 24
            for _ in range(8):
                msb = crc >> 31
                crc <<= 1
                crc ^= (0 - msb) & 0x104C11DB7
        return crc

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Raises:
            ValueError: Invalid `packet_start_code_prefix`
            ValueError: Invalid `map_stream_id`
            ValueError: Reserved Stream Type 0x00 detected

        Returns:
            Self: PS Program Stream Map
        """

        packet_start_code_prefix: bytes = stream.read("bytes:3")
        if packet_start_code_prefix != PACKET_START_CODE:
            raise ValueError("Invalid `packet_start_code_prefix`.")
        map_stream_id: int = stream.read("uint:8")
        if map_stream_id != 0xBC:
            raise ValueError("Invalid `map_stream_id`.")
        program_stream_map_length: int = stream.read("uintbe:16")
        program_stream_map_stream = BitStream(
            stream.read(8 * program_stream_map_length)
        )

        current_next_indicator: int = program_stream_map_stream.read("uint:1")
        # Skip Reserved
        program_stream_map_stream.pos += 2
        program_stream_map_version = program_stream_map_stream.read("uint:5")
        # Skip Reserved and marker_bit
        program_stream_map_stream.pos += 8

        program_stream_info: list[Mpeg2Descriptor] = []
        program_stream_info_length: int = program_stream_map_stream.read("uintbe:16")
        program_stream_info_stream = BitStream(
            program_stream_map_stream.read(8 * program_stream_info_length)
        )
        while True:
            descriptor = read_descriptor(program_stream_info_stream)
            if descriptor is None:
                break
            program_stream_info.append(descriptor)

        elementary_stream_map: list[Mpeg2PsElementaryStreamMapEntry] = []
        elementary_stream_map_length: int = program_stream_map_stream.read("uintbe:16")
        elementary_stream_map_stream = BitStream(
            program_stream_map_stream.read(8 * elementary_stream_map_length)
        )
        while True:
            stream_type: int
            try:
                stream_type = elementary_stream_map_stream.read("uint:8")
            except ReadError:
                # End of Stream
                break
            if stream_type == 0x00:
                raise ValueError("Reserved Stream Type 0x00 detected.")
            elementary_stream_id = elementary_stream_map_stream.read("uint:8")

            elementary_stream_info: list[Mpeg2Descriptor] = []
            elementary_stream_info_length: int = elementary_stream_map_stream.read(
                "uintbe:16"
            )
            elementary_stream_info_stream = BitStream(
                elementary_stream_map_stream.read(8 * elementary_stream_info_length)
            )
            while True:
                descriptor = read_descriptor(elementary_stream_info_stream)
                if descriptor is None:
                    break
                elementary_stream_info.append(descriptor)
            elementary_stream_map.append(
                Mpeg2PsElementaryStreamMapEntry(
                    stream_type, elementary_stream_id, elementary_stream_info
                )
            )

        crc32 = program_stream_map_stream.read("uintbe:32")

        return cls(
            current_next_indicator,
            program_stream_map_version,
            program_stream_info,
            elementary_stream_map,
        )

    def write(self, stream: BitStream) -> None:
        stream.append(PACKET_START_CODE + b"\xbc")

        program_stream_map_stream = BitStream()
        program_stream_map_stream.append(pack("uint:1", self.current_next_indicator))
        # Reserved
        program_stream_map_stream.append(BitArray(bin="11"))
        program_stream_map_stream.append(
            pack("uint:5", self.program_stream_map_version)
        )
        # Reserved and marker_bit
        program_stream_map_stream.append(b"\xff")

        program_stream_info_stream = BitStream()
        for descriptor in self.program_stream_info:
            descriptor.write(program_stream_info_stream)
        program_stream_info_buffer = program_stream_info_stream.tobytes()
        program_stream_map_stream.append(
            pack("uintbe:16", len(program_stream_info_buffer))
        )
        program_stream_map_stream.append(program_stream_info_buffer)

        elementary_stream_map_stream = BitStream()
        for entry in self.elementary_stream_map:
            elementary_stream_map_stream.append(pack("uint:8", entry.stream_type))
            elementary_stream_map_stream.append(
                pack("uint:8", entry.elementary_stream_id)
            )

            elementary_stream_info_stream = BitStream()
            for descriptor in entry.elementary_stream_info:
                descriptor.write(elementary_stream_info_stream)
            elementary_stream_info_buffer = elementary_stream_info_stream.tobytes()
            elementary_stream_map_stream.append(
                pack("uintbe:16", len(elementary_stream_info_buffer))
            )
            elementary_stream_map_stream.append(elementary_stream_info_buffer)
        elementary_stream_map_buffer = elementary_stream_map_stream.tobytes()
        program_stream_map_stream.append(
            pack("uintbe:16", len(elementary_stream_map_buffer))
        )
        program_stream_map_stream.append(elementary_stream_map_buffer)

        program_stream_map_buffer = program_stream_map_stream.tobytes()
        stream.append(pack("uintbe:16", len(program_stream_map_buffer) + 4))
        stream.append(program_stream_map_buffer)

        buffer = stream.tobytes()
        crc32 = Mpeg2PsProgramStreamMap.__crc32(buffer)
        stream.append(pack("uintbe:32", crc32))


Mpeg2PsPacket = Union[
    Mpeg2PsProgramEnd,
    Mpeg2PsPackHeader,
    Mpeg2PsSystemHeader,
    Mpeg2PsProgramStreamMap,
    Mpeg2PesPacket,
]


def seek_packet(stream: BitStream, packet_id: int | None = None) -> int | None:
    """Seek Packet

    Args:
        stream (BitStream): Input stream
        packet_id (int | None, optional): Packet ID. Defaults to None.

    Returns:
        int | None: int if found Packet ID, else Packet not found
    """

    zero_count = 0
    while True:
        current_byte: int
        try:
            current_byte = stream.read("uint:8")
        except ReadError:
            # End of Stream
            break
        if 2 <= zero_count and current_byte == 0x01:
            try:
                current_byte = stream.read("uint:8")
            except ReadError:
                # End of Stream
                break
            if packet_id is None:
                stream.bytepos -= 4
                return current_byte
            else:
                if current_byte == packet_id:
                    stream.bytepos -= 4
                    return current_byte
        # Count zero
        if current_byte == 0x00:
            zero_count += 1
        else:
            zero_count = 0


def index_packets(
    stream: BitStream, packet_id: int | None = None
) -> list[tuple[int, int]]:
    """Index Packets

    Args:
        stream (BitStream): Input stream
        packet_id (int | None, optional): Packet ID. Defaults to None.

    Returns:
        list[tuple[int, int]]: Index of Packet
    """

    index: list[tuple[int, int]] = []

    last_position = -1
    while True:
        packet_id = seek_packet(stream, packet_id)
        if packet_id is None:
            break
        if last_position != -1:
            index.append((last_position, stream.bytepos - last_position))
        last_position = stream.bytepos
        stream.bytepos += 4

    if last_position != -1:
        index.append((last_position, stream.bytepos - last_position))

    return index


def peek_packet_id(stream: BitStream) -> int:
    """Peek Packet ID

    Args:
        stream (BitStream): Input stream

    Raises:
        ValueError: Invalid packet start code

    Returns:
        int: Packet ID
    """

    buffer: bytes = stream.peek("bytes:4")
    if buffer[0:3] != PACKET_START_CODE:
        raise ValueError("Invalid packet start code.")
    return buffer[3]


def read_ps_packet(stream: BitStream) -> Mpeg2PsPacket | None:
    """Read PS Packet

    Args:
        stream (BitStream): Input stream

    Returns:
        Mpeg2PsPacket | None: Mpeg2PsPacket if found PS Packet, else PS Packet not found
    """

    packet_id = seek_packet(stream)
    if packet_id is None:
        return

    if packet_id == 0xB9:
        return Mpeg2PsProgramEnd.read(stream)
    elif packet_id == 0xBA:
        return Mpeg2PsPackHeader.read(stream)
    elif packet_id == 0xBB:
        return Mpeg2PsSystemHeader.read(stream)
    elif packet_id == 0xBC:
        return Mpeg2PsProgramStreamMap.read(stream)
    else:
        return read_pes_packet(stream)
