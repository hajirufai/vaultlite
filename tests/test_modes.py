"""Tests for AES-CBC mode of operation."""

import os
import unittest

from vaultlite.crypto.aes import AES128, BLOCK_SIZE
from vaultlite.crypto.modes import encrypt_cbc, decrypt_cbc
from vaultlite.errors import CryptoError, PaddingError


class TestCBCMode(unittest.TestCase):
    """Test CBC encryption and decryption."""

    def setUp(self):
        self.key = os.urandom(16)
        self.aes = AES128(self.key)

    def test_round_trip_single_block(self):
        """Encrypt/decrypt data that fits in one block."""
        plaintext = b"hello world!!!!!"  # 16 bytes
        encrypted = encrypt_cbc(self.aes, plaintext)
        decrypted = decrypt_cbc(self.aes, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_round_trip_multi_block(self):
        """Encrypt/decrypt data spanning multiple blocks."""
        plaintext = b"This is a longer message that spans multiple AES blocks easily!"
        encrypted = encrypt_cbc(self.aes, plaintext)
        decrypted = decrypt_cbc(self.aes, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_round_trip_short_data(self):
        """Encrypt/decrypt data shorter than one block."""
        plaintext = b"hi"
        encrypted = encrypt_cbc(self.aes, plaintext)
        decrypted = decrypt_cbc(self.aes, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_round_trip_empty(self):
        """Encrypt/decrypt empty data."""
        plaintext = b""
        encrypted = encrypt_cbc(self.aes, plaintext)
        decrypted = decrypt_cbc(self.aes, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_iv_prepended(self):
        """Encrypted output starts with the IV (16 bytes)."""
        plaintext = b"test data"
        iv = os.urandom(16)
        encrypted = encrypt_cbc(self.aes, plaintext, iv=iv)
        self.assertEqual(encrypted[:16], iv)

    def test_random_iv_each_time(self):
        """Different IVs produce different ciphertexts."""
        plaintext = b"same message"
        ct1 = encrypt_cbc(self.aes, plaintext)
        ct2 = encrypt_cbc(self.aes, plaintext)
        self.assertNotEqual(ct1, ct2)  # Random IVs should differ

    def test_ciphertext_is_block_aligned(self):
        """Ciphertext (minus IV) is always a multiple of block size."""
        for size in [0, 1, 15, 16, 17, 31, 32, 100]:
            plaintext = os.urandom(size)
            encrypted = encrypt_cbc(self.aes, plaintext)
            ct_len = len(encrypted) - BLOCK_SIZE  # minus IV
            self.assertEqual(ct_len % BLOCK_SIZE, 0)

    def test_invalid_iv_length(self):
        with self.assertRaises(CryptoError):
            encrypt_cbc(self.aes, b"test", iv=b"short")

    def test_data_too_short(self):
        with self.assertRaises(CryptoError):
            decrypt_cbc(self.aes, b"short")

    def test_wrong_key_fails(self):
        """Decrypting with the wrong key should fail or give garbage."""
        plaintext = b"secret message"
        encrypted = encrypt_cbc(self.aes, plaintext)
        wrong_aes = AES128(os.urandom(16))
        with self.assertRaises(PaddingError):
            decrypt_cbc(wrong_aes, encrypted)

    def test_tampered_ciphertext_fails(self):
        """Flipping a ciphertext bit should break decryption."""
        plaintext = b"important data!!"
        encrypted = bytearray(encrypt_cbc(self.aes, plaintext))
        # Flip a bit in the ciphertext (after IV)
        encrypted[20] ^= 0x01
        # May raise PaddingError or produce garbage
        try:
            result = decrypt_cbc(self.aes, bytes(encrypted))
            # If it doesn't raise, the data should be different
            self.assertNotEqual(result, plaintext)
        except PaddingError:
            pass  # Expected

    def test_large_data(self):
        """Encrypt/decrypt 1KB of data."""
        plaintext = os.urandom(1024)
        encrypted = encrypt_cbc(self.aes, plaintext)
        decrypted = decrypt_cbc(self.aes, encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_binary_data(self):
        """Encrypt/decrypt all byte values."""
        plaintext = bytes(range(256))
        encrypted = encrypt_cbc(self.aes, plaintext)
        decrypted = decrypt_cbc(self.aes, encrypted)
        self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main()
