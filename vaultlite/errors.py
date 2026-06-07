"""Custom exceptions for VaultLite."""


class VaultLiteError(Exception):
    """Base exception for all VaultLite errors."""
    pass


class SealedError(VaultLiteError):
    """Vault is sealed — cannot perform operations until unsealed."""

    def __init__(self, message: str = "Vault is sealed"):
        super().__init__(message)


class AuthenticationError(VaultLiteError):
    """Authentication failed — invalid or expired token."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)


class AuthorizationError(VaultLiteError):
    """Authorization failed — token lacks required capability."""

    def __init__(self, message: str = "Permission denied"):
        super().__init__(message)


class SecretNotFoundError(VaultLiteError):
    """Secret path does not exist."""

    def __init__(self, path: str):
        super().__init__(f"Secret not found: {path}")
        self.path = path


class VersionNotFoundError(VaultLiteError):
    """Specific version of a secret does not exist."""

    def __init__(self, path: str, version: int):
        super().__init__(f"Version {version} not found for: {path}")
        self.path = path
        self.version = version


class CryptoError(VaultLiteError):
    """Encryption or decryption failure."""
    pass


class PaddingError(CryptoError):
    """Invalid PKCS7 padding detected."""

    def __init__(self, message: str = "Invalid padding"):
        super().__init__(message)


class PolicyError(VaultLiteError):
    """Invalid policy definition or evaluation failure."""
    pass


class LeaseError(VaultLiteError):
    """Lease expired, invalid, or cannot be renewed."""
    pass


class InitializationError(VaultLiteError):
    """Vault initialization error — already initialized or not initialized."""
    pass
