from bitstring import BitStream
import logging

# 256 KiB
__BLOCK_SIZE = 262144

__logger = logging.getLogger(__name__)


def copy(source: BitStream, destination: BitStream, length: int | None = None) -> None:
    """Copr data between BitStream

    Args:
        source (BitStream): Source
        destination (BitStream): Destination
        length (int | None, optional): Length. Defaults to None.
    """

    if length is None:
        length = len(source) // 8 - source.bytepos

    blocks = length // __BLOCK_SIZE
    fraction = length % __BLOCK_SIZE
    __logger.debug(f"Parameters calculated. blocks={blocks} fraction={fraction}")
    for _ in range(blocks):
        destination.append(source.read(8 * __BLOCK_SIZE))
    destination.append(source.read(8 * fraction))
