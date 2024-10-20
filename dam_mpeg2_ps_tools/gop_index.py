from bitstring import BitStream, pack
from dataclasses import dataclass
from logging import getLogger
from typing import Self

__logger = getLogger(__name__)


@dataclass
class GopIndexEntry:
    """GOP Index entry"""

    ps_pack_header_position: int
    access_unit_size: int
    pts: int


@dataclass
class GopIndex:
    """GOP Index"""

    sub_stream_id: int
    version: int
    stream_id: int
    page_number: int
    page_count: int
    gops: list[GopIndexEntry]

    @classmethod
    def read(cls, stream: BitStream) -> Self:
        """Read

        Args:
            stream (BitStream): Input stream

        Returns:
            Self: GOP Index
        """

        sub_stream_id: int = stream.read("uint:8")
        version: int = stream.read("uint:8")
        stream_id: int = stream.read("uint:8")
        page_number: int = stream.read("uint:4")
        page_count: int = stream.read("uint:4")
        gop_count: int = stream.read("uintbe:16") + 1
        gops: list[GopIndexEntry] = []
        for _ in range(gop_count):
            ps_pack_header_position: int = stream.read("uintbe:40")
            access_unit_size: int = stream.read("uintbe:24")
            pts: int = stream.read("uintbe:32")
            gops.append(GopIndexEntry(ps_pack_header_position, access_unit_size, pts))

        return cls(sub_stream_id, version, stream_id, page_number, page_count, gops)

    def write(self, stream: BitStream) -> None:
        """Write

        Args:
            stream (BitStream): Output stream
        """

        header_bytes = pack(
            "uint:8, uint:8, uint:8, uint:4, uint:4, uintbe:16",
            self.sub_stream_id,
            self.version,
            self.stream_id,
            self.page_number,
            self.page_count,
            len(self.gops) - 1,
        )
        stream.append(header_bytes)
        for gop in self.gops:
            gop_entry_bytes = pack(
                "uintbe:40, uintbe:24, uintbe:32",
                gop.ps_pack_header_position,
                gop.access_unit_size,
                gop.pts,
            )
            stream.append(gop_entry_bytes)

    def to_bytes(self) -> bytes:
        """To bytes

        Returns:
            bytes: GOP Index as bytes
        """

        stream = BitStream()
        self.write(stream)
        return stream.tobytes()
