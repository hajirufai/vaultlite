"""VaultLite — A lightweight secrets manager with AES built from scratch.

Zero external dependencies. Pure Python standard library.
"""

__version__ = "1.0.0"
__author__ = "Haji Rufai"

from vaultlite.vault import Vault
from vaultlite.types import Secret, Policy, Token, Lease, AuditEntry
from vaultlite.errors import (
    VaultLiteError,
    SealedError,
    AuthenticationError,
    AuthorizationError,
    SecretNotFoundError,
    CryptoError,
)

__all__ = [
    "Vault",
    "Secret",
    "Policy",
    "Token",
    "Lease",
    "AuditEntry",
    "VaultLiteError",
    "SealedError",
    "AuthenticationError",
    "AuthorizationError",
    "SecretNotFoundError",
    "CryptoError",
]
