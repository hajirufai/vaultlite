"""Tests for HMAC-SHA256 message authentication."""

import os
import unittest

from vaultlite.crypto.mac import hmac_sign, hmac_verify


class TestHMAC(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(32)

    def test_sign_returns_hex(self):
        mac = hmac_sign(self.key, b"test data")
        self.assertEqual(len(mac), 64)  # SHA-256 = 32 bytes = 64 hex chars
        int(mac, 16)  # Should parse as hex

    def test_verify_valid(self):
        data = b"important message"
        mac = hmac_sign(self.key, data)
        self.assertTrue(hmac_verify(self.key, data, mac))

    def test_verify_tampered_data(self):
        data = b"original"
        mac = hmac_sign(self.key, data)
        self.assertFalse(hmac_verify(self.key, b"tampered", mac))

    def test_verify_wrong_mac(self):
        data = b"data"
        self.assertFalse(hmac_verify(self.key, data, "a" * 64))

    def test_verify_wrong_key(self):
        data = b"data"
        mac = hmac_sign(self.key, data)
        wrong_key = os.urandom(32)
        self.assertFalse(hmac_verify(wrong_key, data, mac))

    def test_deterministic(self):
        data = b"same data"
        mac1 = hmac_sign(self.key, data)
        mac2 = hmac_sign(self.key, data)
        self.assertEqual(mac1, mac2)

    def test_different_data_different_mac(self):
        mac1 = hmac_sign(self.key, b"data1")
        mac2 = hmac_sign(self.key, b"data2")
        self.assertNotEqual(mac1, mac2)

    def test_empty_data(self):
        mac = hmac_sign(self.key, b"")
        self.assertTrue(hmac_verify(self.key, b"", mac))


if __name__ == "__main__":
    unittest.main()
