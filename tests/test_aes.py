"""Tests for AES-128 block cipher implementation.

Includes NIST FIPS 197 Appendix B test vector for validation.
"""

import os
import unittest

from vaultlite.crypto.aes import (
    AES128,
    BLOCK_SIZE,
    _xtime,
    _multiply,
    _sub_bytes,
    _inv_sub_bytes,
    _shift_rows,
    _inv_shift_rows,
    _mix_columns,
    _inv_mix_columns,
    _bytes_to_state,
    _state_to_bytes,
    _SBOX,
    _INV_SBOX,
)
from vaultlite.errors import CryptoError


class TestSBox(unittest.TestCase):
    """Test the S-box and inverse S-box tables."""

    def test_sbox_is_permutation(self):
        """S-box must be a bijection (permutation of 0-255)."""
        self.assertEqual(sorted(_SBOX), list(range(256)))

    def test_inv_sbox_is_inverse(self):
        """InvSBox(SBox(x)) == x for all x."""
        for x in range(256):
            self.assertEqual(_INV_SBOX[_SBOX[x]], x)

    def test_sbox_known_values(self):
        """Check known S-box values from FIPS 197."""
        self.assertEqual(_SBOX[0x00], 0x63)
        self.assertEqual(_SBOX[0x01], 0x7C)
        self.assertEqual(_SBOX[0x53], 0xED)
        self.assertEqual(_SBOX[0xFF], 0x16)


class TestGF256(unittest.TestCase):
    """Test Galois Field GF(2^8) arithmetic."""

    def test_xtime_basic(self):
        """xtime(a) = a * 2 in GF(2^8)."""
        self.assertEqual(_xtime(0x57), 0xAE)
        self.assertEqual(_xtime(0xAE), 0x47)  # high bit set → XOR 0x1B

    def test_xtime_zero(self):
        self.assertEqual(_xtime(0), 0)

    def test_multiply_identity(self):
        """a * 1 = a."""
        for a in [0x00, 0x01, 0x53, 0xFF]:
            self.assertEqual(_multiply(a, 1), a)

    def test_multiply_zero(self):
        """a * 0 = 0."""
        for a in [0x00, 0x01, 0x53, 0xFF]:
            self.assertEqual(_multiply(a, 0), 0)

    def test_multiply_known(self):
        """Known multiplication results in GF(2^8)."""
        self.assertEqual(_multiply(0x57, 0x13), 0xFE)

    def test_multiply_commutative(self):
        """a * b = b * a."""
        for a, b in [(0x57, 0x83), (0x13, 0xFE), (0x01, 0xFF)]:
            self.assertEqual(_multiply(a, b), _multiply(b, a))


class TestStateConversion(unittest.TestCase):
    """Test bytes ↔ state matrix conversion."""

    def test_round_trip(self):
        data = bytes(range(16))
        state = _bytes_to_state(data)
        result = _state_to_bytes(state)
        self.assertEqual(result, data)

    def test_column_major_order(self):
        """AES state is column-major: byte 0 at [0][0], byte 1 at [1][0]."""
        data = bytes(range(16))
        state = _bytes_to_state(data)
        self.assertEqual(state[0][0], 0)   # b0
        self.assertEqual(state[1][0], 1)   # b1
        self.assertEqual(state[0][1], 4)   # b4
        self.assertEqual(state[3][3], 15)  # b15


class TestSubBytes(unittest.TestCase):
    """Test SubBytes / InvSubBytes transformations."""

    def test_round_trip(self):
        state = [[i * 4 + j for j in range(4)] for i in range(4)]
        original = [row[:] for row in state]
        _sub_bytes(state)
        _inv_sub_bytes(state)
        self.assertEqual(state, original)


class TestShiftRows(unittest.TestCase):
    """Test ShiftRows / InvShiftRows transformations."""

    def test_shift_rows(self):
        state = [
            [0, 1, 2, 3],
            [4, 5, 6, 7],
            [8, 9, 10, 11],
            [12, 13, 14, 15],
        ]
        _shift_rows(state)
        self.assertEqual(state[0], [0, 1, 2, 3])     # no shift
        self.assertEqual(state[1], [5, 6, 7, 4])     # shift left 1
        self.assertEqual(state[2], [10, 11, 8, 9])   # shift left 2
        self.assertEqual(state[3], [15, 12, 13, 14]) # shift left 3

    def test_round_trip(self):
        state = [[i * 4 + j for j in range(4)] for i in range(4)]
        original = [row[:] for row in state]
        _shift_rows(state)
        _inv_shift_rows(state)
        self.assertEqual(state, original)


class TestMixColumns(unittest.TestCase):
    """Test MixColumns / InvMixColumns transformations."""

    def test_round_trip(self):
        state = [[0xDB, 0xF2, 0x01, 0x01],
                 [0x13, 0x0A, 0x01, 0x01],
                 [0x53, 0x22, 0x01, 0x01],
                 [0x45, 0x5C, 0x01, 0x01]]
        original = [row[:] for row in state]
        _mix_columns(state)
        _inv_mix_columns(state)
        self.assertEqual(state, original)

    def test_known_vector(self):
        """Known MixColumns result from FIPS 197."""
        state = [[0xDB, 0x01, 0x01, 0x01],
                 [0x13, 0x01, 0x01, 0x01],
                 [0x53, 0x01, 0x01, 0x01],
                 [0x45, 0x01, 0x01, 0x01]]
        _mix_columns(state)
        self.assertEqual(state[0][0], 0x8E)
        self.assertEqual(state[1][0], 0x4D)
        self.assertEqual(state[2][0], 0xA1)
        self.assertEqual(state[3][0], 0xBC)


class TestAES128(unittest.TestCase):
    """Test full AES-128 encryption and decryption."""

    def test_nist_appendix_b(self):
        """NIST FIPS 197 Appendix B test vector.

        Key:       2b7e151628aed2a6abf7158809cf4f3c
        Plaintext: 3243f6a8885a308d313198a2e0370734
        Expected:  3925841d02dc09fbdc118597196a0b32
        """
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        aes = AES128(key)
        ciphertext = aes.encrypt_block(plaintext)
        self.assertEqual(ciphertext, expected)

    def test_decrypt_nist(self):
        """Decrypt the NIST test vector."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        expected = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

        aes = AES128(key)
        plaintext = aes.decrypt_block(ciphertext)
        self.assertEqual(plaintext, expected)

    def test_encrypt_decrypt_round_trip(self):
        """Encrypt then decrypt should return original plaintext."""
        key = os.urandom(16)
        plaintext = os.urandom(16)
        aes = AES128(key)
        ciphertext = aes.encrypt_block(plaintext)
        recovered = aes.decrypt_block(ciphertext)
        self.assertEqual(recovered, plaintext)

    def test_different_keys_different_ciphertext(self):
        """Same plaintext with different keys → different ciphertext."""
        plaintext = os.urandom(16)
        aes1 = AES128(os.urandom(16))
        aes2 = AES128(os.urandom(16))
        self.assertNotEqual(
            aes1.encrypt_block(plaintext),
            aes2.encrypt_block(plaintext),
        )

    def test_invalid_key_length(self):
        """Key must be exactly 16 bytes."""
        with self.assertRaises(CryptoError):
            AES128(b"short")
        with self.assertRaises(CryptoError):
            AES128(b"this key is way too long for aes128")

    def test_invalid_block_size(self):
        """Blocks must be exactly 16 bytes."""
        aes = AES128(os.urandom(16))
        with self.assertRaises(CryptoError):
            aes.encrypt_block(b"short")
        with self.assertRaises(CryptoError):
            aes.decrypt_block(b"short")

    def test_all_zeros(self):
        """Encrypt all-zero key and plaintext."""
        key = bytes(16)
        plaintext = bytes(16)
        aes = AES128(key)
        ct = aes.encrypt_block(plaintext)
        self.assertNotEqual(ct, plaintext)  # should change
        pt = aes.decrypt_block(ct)
        self.assertEqual(pt, plaintext)

    def test_all_ones(self):
        """Encrypt all-0xFF key and plaintext."""
        key = bytes([0xFF] * 16)
        plaintext = bytes([0xFF] * 16)
        aes = AES128(key)
        ct = aes.encrypt_block(plaintext)
        pt = aes.decrypt_block(ct)
        self.assertEqual(pt, plaintext)

    def test_many_random_round_trips(self):
        """Multiple random key/plaintext round trips."""
        for _ in range(20):
            key = os.urandom(16)
            plaintext = os.urandom(16)
            aes = AES128(key)
            ct = aes.encrypt_block(plaintext)
            pt = aes.decrypt_block(ct)
            self.assertEqual(pt, plaintext)


class TestKeyExpansion(unittest.TestCase):
    """Test AES-128 key expansion."""

    def test_generates_11_round_keys(self):
        """AES-128 needs 11 round keys (initial + 10 rounds)."""
        aes = AES128(os.urandom(16))
        self.assertEqual(len(aes._round_keys), 11)

    def test_each_round_key_is_4x4(self):
        """Each round key is a 4x4 matrix."""
        aes = AES128(os.urandom(16))
        for rk in aes._round_keys:
            self.assertEqual(len(rk), 4)
            for row in rk:
                self.assertEqual(len(row), 4)

    def test_first_round_key_equals_input_key(self):
        """The first round key should be the original key."""
        key = bytes(range(16))
        aes = AES128(key)
        # Reconstruct key from first round key (column-major)
        reconstructed = []
        for c in range(4):
            for r in range(4):
                reconstructed.append(aes._round_keys[0][r][c])
        self.assertEqual(bytes(reconstructed), key)


if __name__ == "__main__":
    unittest.main()
