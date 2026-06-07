"""Secret leasing — TTL-based access control.

When a token reads a secret, it receives a lease granting temporary
access. Leases can be renewed (extended) or revoked (immediately
invalidated). Expired leases are cleaned up automatically.

This provides defense-in-depth: even if a token is compromised,
leaked secrets expire after the lease TTL.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import Optional

from vaultlite.types import Lease
from vaultlite.errors import LeaseError


def _generate_lease_id() -> str:
    """Generate a unique lease identifier."""
    return "lease." + secrets.token_urlsafe(16)


class LeaseManager:
    """Manages secret leases with TTL enforcement."""

    def __init__(self, default_ttl: float = 3600, max_ttl: float = 86400):
        """Initialize lease manager.

        Args:
            default_ttl: Default lease duration in seconds (1 hour).
            max_ttl: Maximum allowed lease duration (24 hours).
        """
        self._leases: dict[str, Lease] = {}
        self._lock = threading.Lock()
        self._default_ttl = default_ttl
        self._max_ttl = max_ttl

    def create_lease(
        self,
        secret_path: str,
        token_id: str,
        ttl: Optional[float] = None,
        renewable: bool = True,
    ) -> Lease:
        """Create a new lease for a secret.

        Args:
            secret_path: Path of the secret being leased.
            token_id: Token that owns the lease.
            ttl: Lease duration in seconds. Uses default if None.
            renewable: Whether the lease can be renewed.

        Returns:
            New Lease instance.
        """
        actual_ttl = min(ttl or self._default_ttl, self._max_ttl)

        lease = Lease(
            lease_id=_generate_lease_id(),
            secret_path=secret_path,
            token_id=token_id,
            ttl=actual_ttl,
            renewable=renewable,
            max_ttl=self._max_ttl,
        )

        with self._lock:
            self._leases[lease.lease_id] = lease

        return lease

    def renew_lease(self, lease_id: str, ttl: Optional[float] = None) -> Lease:
        """Renew (extend) a lease.

        Args:
            lease_id: The lease to renew.
            ttl: New TTL in seconds. Uses the original TTL if None.

        Returns:
            Updated Lease.

        Raises:
            LeaseError: If the lease doesn't exist, is expired,
                revoked, or not renewable.
        """
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                raise LeaseError(f"Lease not found: {lease_id}")
            if lease.revoked:
                raise LeaseError("Lease has been revoked")
            if lease.expired:
                raise LeaseError("Lease has expired")
            if not lease.renewable:
                raise LeaseError("Lease is not renewable")

            new_ttl = min(ttl or lease.ttl, lease.max_ttl)
            lease.ttl = new_ttl
            lease.expires_at = time.time() + new_ttl
            return lease

    def revoke_lease(self, lease_id: str) -> bool:
        """Revoke a lease immediately.

        Returns True if the lease existed and was revoked.
        """
        with self._lock:
            lease = self._leases.get(lease_id)
            if lease is None:
                return False
            lease.revoked = True
            return True

    def revoke_by_path(self, secret_path: str) -> int:
        """Revoke all leases for a given secret path.

        Returns the number of leases revoked.
        """
        count = 0
        with self._lock:
            for lease in self._leases.values():
                if lease.secret_path == secret_path and not lease.revoked:
                    lease.revoked = True
                    count += 1
        return count

    def revoke_by_token(self, token_id: str) -> int:
        """Revoke all leases owned by a token.

        Returns the number of leases revoked.
        """
        count = 0
        with self._lock:
            for lease in self._leases.values():
                if lease.token_id == token_id and not lease.revoked:
                    lease.revoked = True
                    count += 1
        return count

    def lookup_lease(self, lease_id: str) -> Optional[Lease]:
        """Look up a lease by ID."""
        with self._lock:
            return self._leases.get(lease_id)

    def list_leases(self, prefix: str = "") -> list[Lease]:
        """List all active (non-expired, non-revoked) leases."""
        with self._lock:
            return [
                lease for lease in self._leases.values()
                if not lease.expired
                and not lease.revoked
                and lease.secret_path.startswith(prefix)
            ]

    def cleanup_expired(self) -> int:
        """Remove expired and revoked leases. Returns count cleaned."""
        count = 0
        with self._lock:
            expired_ids = [
                lid for lid, lease in self._leases.items()
                if lease.expired or lease.revoked
            ]
            for lid in expired_ids:
                del self._leases[lid]
                count += 1
        return count

    def to_dict(self) -> dict:
        """Serialize lease manager state."""
        return {
            lid: lease.to_dict()
            for lid, lease in self._leases.items()
        }

    def load_from_dict(self, data: dict) -> None:
        """Restore lease manager state."""
        for lid, ldata in data.items():
            self._leases[lid] = Lease.from_dict(ldata)
