"""Tests for PBKDF2 key derivation."""

import unittest

from vaultlite.crypto.kdf import derive_key, generate_salt


class TestGenerateSalt(unittest.TestCase):

    def test_default_length(self):
        salt = generate_salt()
        self.assertEqual(len(salt), 32)

    def test_custom_length(self):
        salt = generate_salt(16)
        self.assertEqual(len(salt), 16)

    def test_salts_are_unique(self):
        salts = {generate_salt() for _ in range(100)}
        self.assertEqual(len(salts), 100)


class TestDeriveKey(unittest.TestCase):

    def test_default_key_length(self):
        key = derive_key("password", generate_salt())
        self.assertEqual(len(key), 16)

    def test_custom_key_length(self):
        key = derive_key("password", generate_salt(), key_length=32)
        self.assertEqual(len(key), 32)

    def test_same_input_same_output(self):
        salt = generate_salt()
        key1 = derive_key("password", salt, iterations=1000)
        key2 = derive_key("password", salt, iterations=1000)
        self.assertEqual(key1, key2)

    def test_different_passwords_different_keys(self):
        salt = generate_salt()
        key1 = derive_key("password1", salt, iterations=1000)
        key2 = derive_key("password2", salt, iterations=1000)
        self.assertNotEqual(key1, key2)

    def test_different_salts_different_keys(self):
        key1 = derive_key("password", generate_salt(), iterations=1000)
        key2 = derive_key("password", generate_salt(), iterations=1000)
        self.assertNotEqual(key1, key2)

    def test_bytes_password(self):
        salt = generate_salt()
        key = derive_key(b"binary password", salt, iterations=1000)
        self.assertEqual(len(key), 16)

    def test_rfc6070_vector_1(self):
        """RFC 6070 Test Vector #1 (truncated to 20 bytes, SHA-1).

        We use SHA-256 so we verify determinism, not exact RFC match.
        """
        salt = b"salt"
        key = derive_key("password", salt, iterations=1, key_length=20)
        self.assertEqual(len(key), 20)
        # Same input should always produce the same output
        key2 = derive_key("password", salt, iterations=1, key_length=20)
        self.assertEqual(key, key2)

    def test_empty_password(self):
        key = derive_key("", generate_salt(), iterations=1000)
        self.assertEqual(len(key), 16)

    def test_unicode_password(self):
        key = derive_key("pässwörd", generate_salt(), iterations=1000)
        self.assertEqual(len(key), 16)


if __name__ == "__main__":
    unittest.main()
