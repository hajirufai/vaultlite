"""AES-128 block cipher — implemented entirely from scratch.

No cryptography libraries, no ctypes, no C extensions. Pure Python
implementation of the Advanced Encryption Standard (Rijndael) with
128-bit keys and 128-bit blocks.

Reference: FIPS 197 — Advanced Encryption Standard (AES)
https://csrc.nist.gov/publications/detail/fips/197/final

NOTE: This is an educational implementation. For production use, prefer
a constant-time, hardware-accelerated implementation like OpenSSL.
"""

from __future__ import annotations

from vaultlite.errors import CryptoError

# Number of rounds for AES-128
_NR = 10

# Block size in bytes (128 bits)
BLOCK_SIZE = 16

# --- Rijndael S-Box ---
# Pre-computed substitution table: multiplicative inverse in GF(2^8)
# followed by an affine transformation.
_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# --- Inverse S-Box (for decryption) ---
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

# --- Round constants (Rcon) ---
# Used in key expansion. Rcon[i] = [rc_i, 0, 0, 0] where rc_1=1,
# rc_i = 2 * rc_{i-1} in GF(2^8).
_RCON = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
]


def _xtime(a: int) -> int:
    """Multiply by x (i.e., by 2) in GF(2^8).

    Left-shift by 1, then XOR with the irreducible polynomial 0x1B
    if the high bit was set (reduction modulo x^8 + x^4 + x^3 + x + 1).
    """
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) using repeated xtime.

    Russian-peasant multiplication: decompose b into powers of 2,
    accumulate a * 2^k for each set bit.
    """
    result = 0
    temp = a
    for _ in range(8):
        if b & 1:
            result ^= temp
        temp = _xtime(temp)
        b >>= 1
    return result


def _sub_bytes(state: list[list[int]]) -> None:
    """SubBytes: substitute each byte using the S-box."""
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _inv_sub_bytes(state: list[list[int]]) -> None:
    """InvSubBytes: substitute each byte using the inverse S-box."""
    for r in range(4):
        for c in range(4):
            state[r][c] = _INV_SBOX[state[r][c]]


def _shift_rows(state: list[list[int]]) -> None:
    """ShiftRows: cyclically shift each row left by its row index.

    Row 0: no shift
    Row 1: shift left by 1
    Row 2: shift left by 2
    Row 3: shift left by 3
    """
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def _inv_shift_rows(state: list[list[int]]) -> None:
    """InvShiftRows: cyclically shift each row right by its row index."""
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]


def _mix_columns(state: list[list[int]]) -> None:
    """MixColumns: matrix multiplication of each column in GF(2^8).

    Each column is multiplied by the fixed polynomial:
    [2, 3, 1, 1]
    [1, 2, 3, 1]
    [1, 1, 2, 3]
    [3, 1, 1, 2]
    """
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]

        state[0][c] = _multiply(2, s0) ^ _multiply(3, s1) ^ s2 ^ s3
        state[1][c] = s0 ^ _multiply(2, s1) ^ _multiply(3, s2) ^ s3
        state[2][c] = s0 ^ s1 ^ _multiply(2, s2) ^ _multiply(3, s3)
        state[3][c] = _multiply(3, s0) ^ s1 ^ s2 ^ _multiply(2, s3)


def _inv_mix_columns(state: list[list[int]]) -> None:
    """InvMixColumns: inverse matrix multiplication of each column in GF(2^8).

    Each column is multiplied by:
    [14, 11, 13,  9]
    [ 9, 14, 11, 13]
    [13,  9, 14, 11]
    [11, 13,  9, 14]
    """
    for c in range(4):
        s0 = state[0][c]
        s1 = state[1][c]
        s2 = state[2][c]
        s3 = state[3][c]

        state[0][c] = (
            _multiply(14, s0) ^ _multiply(11, s1)
            ^ _multiply(13, s2) ^ _multiply(9, s3)
        )
        state[1][c] = (
            _multiply(9, s0) ^ _multiply(14, s1)
            ^ _multiply(11, s2) ^ _multiply(13, s3)
        )
        state[2][c] = (
            _multiply(13, s0) ^ _multiply(9, s1)
            ^ _multiply(14, s2) ^ _multiply(11, s3)
        )
        state[3][c] = (
            _multiply(11, s0) ^ _multiply(13, s1)
            ^ _multiply(9, s2) ^ _multiply(14, s3)
        )


def _add_round_key(state: list[list[int]], round_key: list[list[int]]) -> None:
    """AddRoundKey: XOR the state with the round key."""
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]


def _bytes_to_state(data: bytes) -> list[list[int]]:
    """Convert 16 bytes into a 4x4 state matrix (column-major order).

    AES state layout (column-major):
    [ b0  b4  b8  b12 ]
    [ b1  b5  b9  b13 ]
    [ b2  b6  b10 b14 ]
    [ b3  b7  b11 b15 ]
    """
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state


def _state_to_bytes(state: list[list[int]]) -> bytes:
    """Convert a 4x4 state matrix back to 16 bytes (column-major order)."""
    result = []
    for c in range(4):
        for r in range(4):
            result.append(state[r][c])
    return bytes(result)


class AES128:
    """AES-128 block cipher.

    Encrypts and decrypts single 16-byte blocks using a 16-byte key.
    This is the raw block cipher — use CBC mode (see modes.py) for
    encrypting data longer than one block.

    Example:
        aes = AES128(key=os.urandom(16))
        ciphertext = aes.encrypt_block(b'sixteen bytes!!')
        plaintext = aes.decrypt_block(ciphertext)
    """

    def __init__(self, key: bytes):
        """Initialize AES-128 with a 16-byte key.

        Args:
            key: Exactly 16 bytes (128 bits).

        Raises:
            CryptoError: If key length is not 16 bytes.
        """
        if len(key) != 16:
            raise CryptoError(f"AES-128 requires a 16-byte key, got {len(key)}")
        self._round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> list[list[list[int]]]:
        """Expand the 16-byte key into 11 round keys.

        AES-128 uses 10 rounds + 1 initial AddRoundKey = 11 round keys.
        Each round key is a 4x4 matrix (same shape as the state).

        The expansion works on 32-bit words (columns of the key matrix).
        For AES-128: Nk=4 words in the key, Nr=10 rounds, need 4*(Nr+1)=44 words.
        """
        # Split key into 4 words of 4 bytes each
        words: list[list[int]] = []
        for i in range(4):
            words.append([key[4 * i + j] for j in range(4)])

        # Expand to 44 words
        for i in range(4, 44):
            temp = list(words[i - 1])

            if i % 4 == 0:
                # RotWord: rotate left by 1 byte
                temp = temp[1:] + temp[:1]
                # SubWord: apply S-box to each byte
                temp = [_SBOX[b] for b in temp]
                # XOR with round constant
                rcon = _RCON[i // 4 - 1]
                temp = [temp[j] ^ rcon[j] for j in range(4)]

            # XOR with word Nk positions back
            new_word = [words[i - 4][j] ^ temp[j] for j in range(4)]
            words.append(new_word)

        # Pack 44 words into 11 round keys (4x4 matrices, column-major)
        round_keys = []
        for rk in range(11):
            key_matrix = [[0] * 4 for _ in range(4)]
            for c in range(4):
                word = words[rk * 4 + c]
                for r in range(4):
                    key_matrix[r][c] = word[r]
            round_keys.append(key_matrix)

        return round_keys

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt a single 16-byte block.

        Args:
            plaintext: Exactly 16 bytes.

        Returns:
            16 bytes of ciphertext.

        Raises:
            CryptoError: If plaintext is not exactly 16 bytes.
        """
        if len(plaintext) != BLOCK_SIZE:
            raise CryptoError(
                f"Block must be {BLOCK_SIZE} bytes, got {len(plaintext)}"
            )

        state = _bytes_to_state(plaintext)

        # Initial round key addition
        _add_round_key(state, self._round_keys[0])

        # Rounds 1 through 9
        for rnd in range(1, _NR):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self._round_keys[rnd])

        # Final round (no MixColumns)
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self._round_keys[_NR])

        return _state_to_bytes(state)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt a single 16-byte block.

        Args:
            ciphertext: Exactly 16 bytes.

        Returns:
            16 bytes of plaintext.

        Raises:
            CryptoError: If ciphertext is not exactly 16 bytes.
        """
        if len(ciphertext) != BLOCK_SIZE:
            raise CryptoError(
                f"Block must be {BLOCK_SIZE} bytes, got {len(ciphertext)}"
            )

        state = _bytes_to_state(ciphertext)

        # Initial round key (last round key first)
        _add_round_key(state, self._round_keys[_NR])

        # Rounds 9 through 1 (in reverse)
        for rnd in range(_NR - 1, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, self._round_keys[rnd])
            _inv_mix_columns(state)

        # Final round (no InvMixColumns)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, self._round_keys[0])

        return _state_to_bytes(state)
