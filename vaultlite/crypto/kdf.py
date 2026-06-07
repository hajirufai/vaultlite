"""Key Derivation Function — PBKDF2-HMAC-SHA256.

Derives a cryptographic key from a password using PBKDF2 with
HMAC-SHA256. Uses Python's stdlib hashlib for the underlying
PBKDF2 implementation.

The salt and iteration count are critical for brute-force resistance.
Default: 100,000 iterations (OWASP recommendation for PBKDF2-SHA256).
"""

import hashlib
import os


DEFAULT_ITERATIONS = 100_000
DEFAULT_KEY_LENGTH = 16  # 128 bits for AES-128
DEFAULT_SALT_LENGTH = 32  # 256-bit salt


def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> bytes:
    """Generate a cryptographically secure random salt.

    Args:
        length: Salt length in bytes. Default 32 (256 bits).

    Returns:
        Random bytes suitable for use as a KDF salt.
    """
    return os.urandom(length)


def derive_key(
    password: str | bytes,
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
    key_length: int = DEFAULT_KEY_LENGTH,
) -> bytes:
    """Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: The password or passphrase. Strings are UTF-8 encoded.
        salt: Random salt bytes (use generate_salt()).
        iterations: Number of PBKDF2 iterations. Higher = slower brute force.
        key_length: Desired key length in bytes. 16 for AES-128.

    Returns:
        Derived key bytes of the requested length.

    Example:
        salt = generate_salt()
        key = derive_key("my-master-password", salt)
        aes = AES128(key)
    """
    if isinstance(password, str):
        password = password.encode("utf-8")

    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password,
        salt=salt,
        iterations=iterations,
        dklen=key_length,
    )
