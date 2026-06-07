"""HMAC-SHA256 message authentication.

Provides authenticated encryption via encrypt-then-MAC. The HMAC
covers the ciphertext and IV, ensuring both integrity and authenticity.

Uses Python's stdlib hmac module with constant-time comparison
via hmac.compare_digest to prevent timing attacks.
"""

import hashlib
import hmac as _hmac


def hmac_sign(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 of data.

    Args:
        key: HMAC key (should be at least 16 bytes).
        data: Data to authenticate (typically IV + ciphertext).

    Returns:
        Hex-encoded HMAC digest.
    """
    return _hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, data: bytes, expected_mac: str) -> bool:
    """Verify HMAC-SHA256 of data using constant-time comparison.

    Args:
        key: Same HMAC key used for signing.
        data: Data that was authenticated.
        expected_mac: Hex-encoded HMAC to verify against.

    Returns:
        True if the MAC is valid, False otherwise.
    """
    computed = _hmac.new(key, data, hashlib.sha256).hexdigest()
    return _hmac.compare_digest(computed, expected_mac)
