from dataclasses import dataclass
from typing import Union


@dataclass
class Mpeg2PsProgramEnd:
    pass


@dataclass
class Mpeg2PesPacketType1:
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


@dataclass
class Mpeg2PesPacketType2:
    stream_id: int
    PES_packet_data: bytes


@dataclass
class Mpeg2PesPacketType3:
    stream_id: int
    PES_packet_length: int


Mpeg2PesPacket = Union[Mpeg2PesPacketType1, Mpeg2PesPacketType2, Mpeg2PesPacketType3]


@dataclass
class Mpeg2PsPackHeader:
    system_clock_reference_base: int
    system_clock_reference_extension: int
    program_mux_rate: int
    pack_stuffing_length: int


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


@dataclass
class Mpeg2GenericDescriptor:
    descriptor_tag: int
    data: bytes


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


@dataclass
class Mpeg2AacAudioDescriptor:
    MPEG_2_AAC_profile: int
    MPEG_2_AAC_channel_configuration: int
    MPEG_2_AAC_additional_information: int


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


Mpeg2Descriptor = Union[
    Mpeg2GenericDescriptor,
    Mpeg2AvcVideoDescriptor,
    Mpeg2AacAudioDescriptor,
    Mpeg2HevcVideoDescriptor,
]


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


Mpeg2PsPacket = Union[
    Mpeg2PsProgramEnd,
    Mpeg2PsPackHeader,
    Mpeg2PsSystemHeader,
    Mpeg2PsProgramStreamMap,
    Mpeg2PesPacket,
]
