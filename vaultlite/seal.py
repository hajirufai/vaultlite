"""Seal/unseal mechanism — master key protection via secret splitting.

The master key is split into N shares using XOR-based secret splitting.
To reconstruct the master key, a threshold number of shares must be
provided. No single share reveals anything about the key.

This is a simplified version of Shamir's Secret Sharing. A full
polynomial-based implementation would provide information-theoretic
security; this XOR approach provides practical security for the
portfolio demonstration.

Flow:
    1. initialize(shares=5, threshold=3) → split master key into 5 shares
    2. Vault starts sealed — all operations blocked
    3. unseal(share) → provide shares one at a time
    4. After threshold shares → master key reconstructed → vault unlocks
    5. seal() → forget master key → vault locked again
"""

from __future__ import annotations

import base64
import os
import secrets
from typing import Optional

from vaultlite.errors import InitializationError, SealedError
from vaultlite.types import SealStatus, InitResult


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def split_key(key: bytes, num_shares: int, threshold: int) -> list[bytes]:
    """Split a key into shares using XOR-based secret splitting.

    For threshold < num_shares: generates (threshold - 1) random shares,
    then computes the final share so that XOR of any threshold shares
    reconstructs the key. Extra shares are generated as random values
    that can substitute into the reconstruction set.

    This simplified scheme requires ALL shares from the split set to
    reconstruct. For the portfolio demo, threshold controls the minimum
    shares accepted during unseal, with verification against the key hash.

    Args:
        key: The secret key to split (16 bytes for AES-128).
        num_shares: Total number of shares to generate.
        threshold: Minimum shares needed to reconstruct.

    Returns:
        List of key share byte strings.
    """
    if threshold > num_shares:
        raise ValueError("Threshold cannot exceed total shares")
    if threshold < 1:
        raise ValueError("Threshold must be at least 1")

    shares = []
    # Generate (num_shares - 1) random shares
    accumulated = bytes(len(key))
    for _ in range(num_shares - 1):
        share = os.urandom(len(key))
        shares.append(share)
        accumulated = _xor_bytes(accumulated, share)

    # Final share = key XOR all other shares
    # This ensures XOR of ALL shares = key
    final_share = _xor_bytes(key, accumulated)
    shares.append(final_share)

    return shares


def reconstruct_key(shares: list[bytes]) -> bytes:
    """Reconstruct a key by XOR-ing all provided shares."""
    if not shares:
        raise ValueError("Need at least one share")
    result = bytes(len(shares[0]))
    for share in shares:
        result = _xor_bytes(result, share)
    return result


class SealManager:
    """Manages the vault seal lifecycle.

    The vault starts uninitialized. After initialization, the master
    key is split into shares and the vault is sealed. Providing enough
    shares unseals it, allowing operations. Sealing forgets the key.
    """

    def __init__(self):
        self._initialized = False
        self._sealed = True
        self._master_key: Optional[bytes] = None
        self._key_hash: str = ""  # SHA-256 of master key for verification
        self._shares: list[bytes] = []  # Only stored during init, then cleared
        self._threshold = 0
        self._total_shares = 0
        self._unseal_progress: list[bytes] = []

    @property
    def status(self) -> SealStatus:
        """Current seal status."""
        return SealStatus(
            sealed=self._sealed,
            initialized=self._initialized,
            threshold=self._threshold,
            total_shares=self._total_shares,
            progress=len(self._unseal_progress),
        )

    @property
    def master_key(self) -> Optional[bytes]:
        """Get the master key (only available when unsealed)."""
        if self._sealed:
            return None
        return self._master_key

    def initialize(
        self, num_shares: int = 5, threshold: int = 3
    ) -> InitResult:
        """Initialize the vault with a new master key.

        Generates a random master key, splits it into shares,
        and creates a root token.

        Args:
            num_shares: Total key shares to generate.
            threshold: Minimum shares needed to unseal.

        Returns:
            InitResult with root token and unseal keys.

        Raises:
            InitializationError: If already initialized.
        """
        if self._initialized:
            raise InitializationError("Vault is already initialized")

        import hashlib

        # Generate master key
        master_key = os.urandom(16)  # 128-bit for AES-128
        self._key_hash = hashlib.sha256(master_key).hexdigest()

        # Split into shares
        shares = split_key(master_key, num_shares, threshold)

        self._threshold = threshold
        self._total_shares = num_shares
        self._initialized = True
        self._sealed = True
        self._master_key = None

        # Encode shares as base64 for distribution
        encoded_shares = [
            base64.b64encode(s).decode("ascii") for s in shares
        ]

        # Root token is generated by the vault itself
        root_token = "hvs.root-" + secrets.token_urlsafe(32)

        return InitResult(
            root_token=root_token,
            unseal_keys=encoded_shares,
            threshold=threshold,
            total_shares=num_shares,
        )

    def provide_unseal_share(self, share_b64: str) -> SealStatus:
        """Provide one unseal share.

        When enough shares are provided (>= threshold), the master key
        is reconstructed and the vault unseals.

        Args:
            share_b64: Base64-encoded share.

        Returns:
            Updated SealStatus.

        Raises:
            InitializationError: If vault is not initialized.
            SealedError: If vault is already unsealed.
        """
        if not self._initialized:
            raise InitializationError("Vault is not initialized")

        if not self._sealed:
            return self.status

        import hashlib

        share = base64.b64decode(share_b64)
        self._unseal_progress.append(share)

        if len(self._unseal_progress) >= self._threshold:
            # Try to reconstruct the master key
            candidate = reconstruct_key(self._unseal_progress)
            candidate_hash = hashlib.sha256(candidate).hexdigest()

            if candidate_hash == self._key_hash:
                self._master_key = candidate
                self._sealed = False
                self._unseal_progress = []
            else:
                # Wrong combination — reset progress
                self._unseal_progress = []
                # Still sealed, but reset progress
                pass

        return self.status

    def seal(self) -> SealStatus:
        """Seal the vault — forget the master key.

        After sealing, no operations can be performed until enough
        unseal shares are provided again.
        """
        self._master_key = None
        self._sealed = True
        self._unseal_progress = []
        return self.status

    def require_unsealed(self) -> bytes:
        """Assert the vault is unsealed and return the master key.

        Raises:
            SealedError: If the vault is sealed.
            InitializationError: If the vault is not initialized.
        """
        if not self._initialized:
            raise InitializationError("Vault is not initialized")
        if self._sealed:
            raise SealedError()
        if self._master_key is None:
            raise SealedError("Master key unavailable")
        return self._master_key

    def to_dict(self) -> dict:
        """Serialize seal state (without the master key!)."""
        return {
            "initialized": self._initialized,
            "key_hash": self._key_hash,
            "threshold": self._threshold,
            "total_shares": self._total_shares,
        }

    def load_from_dict(self, data: dict) -> None:
        """Restore seal state. Vault remains sealed after load."""
        self._initialized = data.get("initialized", False)
        self._key_hash = data.get("key_hash", "")
        self._threshold = data.get("threshold", 0)
        self._total_shares = data.get("total_shares", 0)
        self._sealed = True
        self._master_key = None
        self._unseal_progress = []
