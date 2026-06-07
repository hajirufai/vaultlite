"""PKCS7 padding for block ciphers.

PKCS7 pads data to a multiple of the block size. Each padding byte
equals the number of padding bytes added. For example, with block
size 16 and 11 data bytes, 5 padding bytes of value 0x05 are appended.

If the data is already block-aligned, a full block of padding is added
(16 bytes of 0x10) to ensure unambiguous removal.
"""

from vaultlite.errors import PaddingError


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Add PKCS7 padding to data.

    Args:
        data: Data to pad.
        block_size: Block size in bytes (1-255).

    Returns:
        Padded data whose length is a multiple of block_size.
    """
    if not 1 <= block_size <= 255:
        raise PaddingError(f"Block size must be 1-255, got {block_size}")

    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Remove and validate PKCS7 padding.

    Args:
        data: Padded data.
        block_size: Block size in bytes.

    Returns:
        Data with padding removed.

    Raises:
        PaddingError: If padding is invalid (wrong length, inconsistent
            bytes, or zero padding value). This may indicate tampering.
    """
    if not data:
        raise PaddingError("Cannot unpad empty data")

    if len(data) % block_size != 0:
        raise PaddingError("Data length is not a multiple of block size")

    pad_byte = data[-1]

    if pad_byte == 0 or pad_byte > block_size:
        raise PaddingError(f"Invalid padding byte: {pad_byte}")

    # Verify all padding bytes are consistent
    for i in range(1, pad_byte + 1):
        if data[-i] != pad_byte:
            raise PaddingError("Inconsistent padding bytes")

    return data[:-pad_byte]
