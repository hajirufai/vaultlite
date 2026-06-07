"""Tests for envelope encryption."""

import os
import unittest

from vaultlite.crypto.envelope import EnvelopeEncryption
from vaultlite.errors import CryptoError


class TestEnvelopeEncryption(unittest.TestCase):

    def setUp(self):
        self.master_key = os.urandom(16)
        self.envelope = EnvelopeEncryption(self.master_key)

    def test_encrypt_decrypt_round_trip(self):
        plaintext = b"database_password=hunter2"
        payload = self.envelope.encrypt(plaintext)
        recovered = self.envelope.decrypt(payload)
        self.assertEqual(recovered, plaintext)

    def test_different_encryptions_different_output(self):
        """Each encryption uses a fresh DEK → different ciphertext."""
        plaintext = b"same data"
        p1 = self.envelope.encrypt(plaintext)
        p2 = self.envelope.encrypt(plaintext)
        self.assertNotEqual(p1.ciphertext, p2.ciphertext)
        self.assertNotEqual(p1.encrypted_dek, p2.encrypted_dek)

    def test_payload_has_all_fields(self):
        payload = self.envelope.encrypt(b"test")
        self.assertTrue(payload.ciphertext)
        self.assertTrue(payload.iv)
        self.assertTrue(payload.hmac)
        self.assertTrue(payload.encrypted_dek)

    def test_tampered_ciphertext_detected(self):
        payload = self.envelope.encrypt(b"secret")
        # Tamper with ciphertext
        import base64
        ct = bytearray(base64.b64decode(payload.ciphertext))
        ct[0] ^= 0xFF
        payload.ciphertext = base64.b64encode(bytes(ct)).decode("ascii")
        with self.assertRaises(CryptoError):
            self.envelope.decrypt(payload)

    def test_tampered_hmac_detected(self):
        payload = self.envelope.encrypt(b"secret")
        payload.hmac = "a" * 64
        with self.assertRaises(CryptoError):
            self.envelope.decrypt(payload)

    def test_wrong_master_key(self):
        payload = self.envelope.encrypt(b"secret")
        wrong_envelope = EnvelopeEncryption(os.urandom(16))
        with self.assertRaises(CryptoError):
            wrong_envelope.decrypt(payload)

    def test_empty_plaintext(self):
        payload = self.envelope.encrypt(b"")
        recovered = self.envelope.decrypt(payload)
        self.assertEqual(recovered, b"")

    def test_large_plaintext(self):
        plaintext = os.urandom(10000)
        payload = self.envelope.encrypt(plaintext)
        recovered = self.envelope.decrypt(payload)
        self.assertEqual(recovered, plaintext)

    def test_invalid_master_key_length(self):
        with self.assertRaises(CryptoError):
            EnvelopeEncryption(b"short")

    def test_master_key_rotation(self):
        # Encrypt several secrets
        secrets_data = [os.urandom(100) for _ in range(5)]
        payloads = [self.envelope.encrypt(s) for s in secrets_data]

        # Rotate to new master key
        new_key = os.urandom(16)
        rotated = self.envelope.rotate_master_key(new_key, payloads)

        # Decrypt with new key
        new_envelope = EnvelopeEncryption(new_key)
        for original, rotated_payload in zip(secrets_data, rotated):
            recovered = new_envelope.decrypt(rotated_payload)
            self.assertEqual(recovered, original)

        # Old key should NOT work on rotated payloads
        for rp in rotated:
            with self.assertRaises(CryptoError):
                self.envelope.decrypt(rp)

    def test_payload_serialization(self):
        payload = self.envelope.encrypt(b"test serialization")
        d = payload.to_dict()
        from vaultlite.types import EncryptedPayload
        restored = EncryptedPayload.from_dict(d)
        recovered = self.envelope.decrypt(restored)
        self.assertEqual(recovered, b"test serialization")


if __name__ == "__main__":
    unittest.main()
