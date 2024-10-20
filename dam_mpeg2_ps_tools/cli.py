from bitstring import BitStream
from decimal import Decimal
import fire
from io import BufferedReader
import logging

from .dam_mpeg2_ps import write_mpeg2_ps
from .gop_index import GopIndex
from .h264_annex_b import H264NalUnit, index_nal_unit
from .mpeg2_ps import read_ps_packet, Mpeg2PesPacketType2


class Cli:
    """DAM MPEG2-PS Tools CLI

    Args:
        log_level (str, optional): Log level. Defaults to "INFO". {CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTSET}
    """

    @staticmethod
    def __config_logger(level: str) -> None:
        """Config logger

        Args:
            level (str): Log level
        """

        logging.basicConfig(
            level=level,
            format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
        )

    @staticmethod
    def __load_h264_es(stream: BufferedReader) -> list[H264NalUnit]:
        """Load H.264-ES

        Args:
            stream (BufferedReader): Input stream

        Returns:
            list[H264NalUnit]: List of H.264 NAL Unit
        """

        nal_units: list[H264NalUnit] = []
        nal_unit_index = index_nal_unit(stream)
        for nal_unit_position, nal_unit_size in nal_unit_index:
            stream.seek(nal_unit_position)
            nal_unit_buffer: bytes = stream.read(nal_unit_size)
            nal_unit = H264NalUnit.from_bytes(nal_unit_buffer)
            if nal_unit is None:
                continue
            nal_units.append(nal_unit)
        return nal_units

    def __init__(self, log_level="INFO"):
        """DAM MPEG2-PS Tools CLI

        Args:
            log_level (str, optional): Log level. Defaults to "INFO". {CRITICAL|FATAL|ERROR|WARN|WARNING|INFO|DEBUG|NOTSET}
        """

        Cli.__config_logger(log_level)
        self.__logger = logging.getLogger(__name__)

    def dump(self, input, print_packets=False) -> None:
        """Dump

        Args:
            input (str): Input MPEG2-PS path
            print_packets (bool, optional): Print packets. Defaults to False.

        Raises:
            ValueError: Invalid argument `input`
            ValueError: Invalid argument `print_packets`
        """

        if not isinstance(input, str):
            raise ValueError("Argument `input` must be str.")
        if not isinstance(print_packets, bool):
            raise ValueError("Argument `print_packets` must be bool.")

        with open(input, "rb") as file:
            stream = BitStream(file)

            while True:
                ps_packet = read_ps_packet(stream)
                if ps_packet is None:
                    self.__logger.debug("No PS Packet. Maybe reached to End of Stream.")
                    break

                if print_packets:
                    print(ps_packet)

                # GOP index packet
                if (
                    isinstance(ps_packet, Mpeg2PesPacketType2)
                    and ps_packet.stream_id == 0xBF
                ):
                    self.__logger.debug("GOP Index Packet (0xBF) found.")
                    data_stream = BitStream(ps_packet.PES_packet_data)
                    gop_index = GopIndex.read(data_stream)
                    if gop_index is None:
                        print("Failed to read GOP index.")
                        continue
                    print(
                        f"gop_index: sub_stream_id={gop_index.sub_stream_id} version={gop_index.version} stream_id={gop_index.stream_id} page_number={gop_index.page_number} page_count={gop_index.page_count}"
                    )
                    if len(gop_index.gops) == 0:
                        continue
                    pts_offset = gop_index.gops[0].pts
                    for index, gop in enumerate(gop_index.gops):
                        print(
                            f"gop_index[{index}]: ps_pack_header_position={gop.ps_pack_header_position} access_unit_size={gop.access_unit_size} pts={gop.pts} pts(msec)={gop.pts / 90} related_pts={gop.pts - pts_offset} related_pts(msec)={(gop.pts - pts_offset) / 90}"
                        )

    def create(self, input, output, codec="avc", frame_rate="30000/1001") -> None:
        """Create

        Args:
            input (str): Input H.264-ES path
            output (str): Output MPEG2-PS path
            codec (str, optional): Codec. Defaults to "avc".
            frame_rate (str, optional): Frame rate. Defaults to "30000/1001". {24000/1001,24,30000/1001,30,60000/1001,60}

        Raises:
            ValueError: Invalid argument `input`
            ValueError: Invalid argument `output`
            ValueError: Invalid argument `codec`
            ValueError: Invalid argument `frame_rate`
        """

        if not isinstance(input, str):
            raise ValueError("Argument `input` must be str.")
        if not isinstance(output, str):
            raise ValueError("Argument `output` must be str.")
        if not isinstance(codec, str):
            raise ValueError("Argument `codec` must be str.")
        if not isinstance(frame_rate, str):
            raise ValueError("Argument `frame_rate` must be str.")

        if frame_rate == "24000/1001":
            frame_rate = Decimal(24000) / 1001
        elif frame_rate == "24":
            frame_rate = Decimal(30)
        elif frame_rate == "30000/1001":
            frame_rate = Decimal(30000) / 1001
        elif frame_rate == "30":
            frame_rate = Decimal(30)
        elif frame_rate == "60000/1001":
            frame_rate = Decimal(60000) / 1001
        elif frame_rate == "60":
            frame_rate = Decimal(60)
        else:
            raise ValueError("Invalid argument `frame_rate`.")

        with open(input, "rb") as input_file, open(output, "wb") as output_file:
            h264_es = Cli.__load_h264_es(input_file)
            output_stream = BitStream()
            write_mpeg2_ps(h264_es, output_stream, codec, frame_rate)
            output_file.write(output_stream.tobytes())


def main() -> None:
    fire.Fire(Cli)


if __name__ == "__main__":
    main()
