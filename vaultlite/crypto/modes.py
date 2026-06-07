"""AES-CBC (Cipher Block Chaining) mode of operation.

CBC mode XORs each plaintext block with the previous ciphertext block
before encryption, providing semantic security (identical plaintexts
produce different ciphertexts due to the random IV).

IV is prepended to the ciphertext for self-contained messages.
"""

from __future__ import annotations

import os

from vaultlite.crypto.aes import AES128, BLOCK_SIZE
from vaultlite.crypto.padding import pkcs7_pad, pkcs7_unpad
from vaultlite.errors import CryptoError


def _xor_blocks(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_cbc(
    aes: AES128,
    plaintext: bytes,
    iv: bytes | None = None,
) -> bytes:
    """Encrypt data using AES-128 in CBC mode with PKCS7 padding.

    Args:
        aes: An initialized AES128 instance.
        plaintext: Data to encrypt (any length).
        iv: 16-byte initialization vector. Generated randomly if None.

    Returns:
        IV (16 bytes) + ciphertext. The IV is prepended so the caller
        doesn't need to track it separately.

    Raises:
        CryptoError: If IV length is invalid.
    """
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)

    if len(iv) != BLOCK_SIZE:
        raise CryptoError(f"IV must be {BLOCK_SIZE} bytes, got {len(iv)}")

    # Pad plaintext to a multiple of the block size
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)

    ciphertext = bytearray()
    prev = iv

    # Encrypt each block: C_i = E(P_i XOR C_{i-1})
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        xored = _xor_blocks(block, prev)
        encrypted = aes.encrypt_block(xored)
        ciphertext.extend(encrypted)
        prev = encrypted

    return bytes(iv) + bytes(ciphertext)


def decrypt_cbc(aes: AES128, data: bytes) -> bytes:
    """Decrypt AES-128-CBC data. Expects IV prepended to ciphertext.

    Args:
        aes: An initialized AES128 instance (same key as encryption).
        data: IV (16 bytes) + ciphertext.

    Returns:
        Decrypted plaintext with PKCS7 padding removed.

    Raises:
        CryptoError: If data is too short or not block-aligned.
        PaddingError: If padding is invalid (possible tampering).
    """
    if len(data) < BLOCK_SIZE * 2:
        raise CryptoError("Data too short — need at least IV + one block")

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise CryptoError("Ciphertext length must be a multiple of block size")

    plaintext = bytearray()
    prev = iv

    # Decrypt each block: P_i = D(C_i) XOR C_{i-1}
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        decrypted = aes.decrypt_block(block)
        plaintext.extend(_xor_blocks(decrypted, prev))
        prev = block

    return pkcs7_unpad(bytes(plaintext), BLOCK_SIZE)
