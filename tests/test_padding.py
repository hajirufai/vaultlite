"""Tests for PKCS7 padding."""

import unittest

from vaultlite.crypto.padding import pkcs7_pad, pkcs7_unpad
from vaultlite.errors import PaddingError


class TestPKCS7Pad(unittest.TestCase):
    """Test PKCS7 padding."""

    def test_pad_needs_full_block(self):
        """Data that's already block-aligned gets a full block of padding."""
        data = b"exactly16bytes!!"
        padded = pkcs7_pad(data, 16)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-1], 16)

    def test_pad_one_byte_short(self):
        data = b"15 bytes here!!"[:15]
        padded = pkcs7_pad(data, 16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-1], 1)

    def test_pad_empty(self):
        padded = pkcs7_pad(b"", 16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded, bytes([16] * 16))

    def test_pad_one_byte(self):
        padded = pkcs7_pad(b"x", 16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-1], 15)

    def test_pad_various_lengths(self):
        for size in range(33):
            padded = pkcs7_pad(b"a" * size, 16)
            self.assertEqual(len(padded) % 16, 0)
            self.assertGreater(len(padded), size)

    def test_invalid_block_size(self):
        with self.assertRaises(PaddingError):
            pkcs7_pad(b"data", 0)
        with self.assertRaises(PaddingError):
            pkcs7_pad(b"data", 256)


class TestPKCS7Unpad(unittest.TestCase):
    """Test PKCS7 unpadding."""

    def test_round_trip(self):
        for size in range(33):
            original = os.urandom(size) if size > 0 else b""
            padded = pkcs7_pad(original, 16)
            unpadded = pkcs7_unpad(padded, 16)
            self.assertEqual(unpadded, original)

    def test_unpad_empty(self):
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"", 16)

    def test_unpad_wrong_length(self):
        with self.assertRaises(PaddingError):
            pkcs7_unpad(b"not aligned", 16)

    def test_unpad_invalid_byte_zero(self):
        """Padding byte of 0 is invalid."""
        data = b"fifteen bytes!!" + b"\x00"
        with self.assertRaises(PaddingError):
            pkcs7_unpad(data, 16)

    def test_unpad_invalid_byte_too_large(self):
        """Padding byte larger than block size is invalid."""
        data = b"fifteen bytes!!" + b"\x11"
        with self.assertRaises(PaddingError):
            pkcs7_unpad(data, 16)

    def test_unpad_inconsistent_bytes(self):
        """All padding bytes must be the same value."""
        # Last byte is \x03, so we need 3 bytes of \x03, but byte[-2] is \x02
        data = b"thirteen byte" + b"\x01\x02\x03"
        with self.assertRaises(PaddingError):
            pkcs7_unpad(data, 16)


import os

if __name__ == "__main__":
    unittest.main()
