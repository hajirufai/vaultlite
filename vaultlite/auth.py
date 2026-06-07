"""Authentication for VaultLite.

Two auth methods:
- Token auth: bearer tokens with policies, TTL, and max uses
- App-role auth: role_id + secret_id → token (for machines)

Tokens form a tree: child tokens are revoked when parent is revoked.
Root tokens have the "root" policy and no expiration by default.
"""

from __future__ import annotations

import secrets
import time
import threading
from typing import Optional

from vaultlite.types import Token
from vaultlite.errors import AuthenticationError


def _generate_token_id() -> str:
    """Generate a secure random token ID (URL-safe, 32 bytes)."""
    return "hvs." + secrets.token_urlsafe(32)


class TokenManager:
    """Manages authentication tokens."""

    def __init__(self):
        self._tokens: dict[str, Token] = {}
        self._lock = threading.Lock()
        # App-role storage: role_id -> {secret_id, policies, ttl}
        self._approles: dict[str, dict] = {}

    def create_root_token(self) -> Token:
        """Create a root token with unlimited access."""
        token = Token(
            token_id=_generate_token_id(),
            policies=["root"],
            is_root=True,
            renewable=False,
        )
        with self._lock:
            self._tokens[token.token_id] = token
        return token

    def create_token(
        self,
        policies: list[str],
        parent_token: Optional[str] = None,
        ttl: Optional[float] = None,
        renewable: bool = True,
        max_uses: int = 0,
        metadata: Optional[dict] = None,
    ) -> Token:
        """Create a child token with specified policies.

        Args:
            policies: Policy names to attach.
            parent_token: Parent token ID (for token tree).
            ttl: Time-to-live in seconds. None = no expiration.
            renewable: Whether the token can be renewed.
            max_uses: Max number of uses (0 = unlimited).
            metadata: Arbitrary key-value metadata.

        Returns:
            New Token instance.
        """
        now = time.time()
        token = Token(
            token_id=_generate_token_id(),
            policies=policies,
            created_at=now,
            expires_at=now + ttl if ttl else None,
            renewable=renewable,
            max_uses=max_uses,
            parent_token=parent_token,
            metadata=metadata or {},
        )
        with self._lock:
            self._tokens[token.token_id] = token
        return token

    def validate_token(self, token_id: str) -> Token:
        """Validate a token and return it if valid.

        Checks: exists, not revoked, not expired, uses not exhausted.
        Increments use count on successful validation.

        Raises:
            AuthenticationError: If the token is invalid.
        """
        with self._lock:
            token = self._tokens.get(token_id)

            if token is None:
                raise AuthenticationError("Invalid token")

            if token.revoked:
                raise AuthenticationError("Token has been revoked")

            if token.expired:
                raise AuthenticationError("Token has expired")

            if token.uses_exhausted:
                raise AuthenticationError("Token max uses exhausted")

            token.use_count += 1
            return token

    def lookup_token(self, token_id: str) -> Optional[Token]:
        """Look up token metadata without incrementing use count."""
        with self._lock:
            return self._tokens.get(token_id)

    def revoke_token(self, token_id: str) -> int:
        """Revoke a token and all its children. Returns count revoked."""
        count = 0
        with self._lock:
            token = self._tokens.get(token_id)
            if token is None:
                return 0

            # BFS to find all children
            to_revoke = [token_id]
            idx = 0
            while idx < len(to_revoke):
                current = to_revoke[idx]
                idx += 1
                t = self._tokens.get(current)
                if t and not t.revoked:
                    t.revoked = True
                    count += 1
                    # Find children
                    for tid, child in self._tokens.items():
                        if child.parent_token == current and not child.revoked:
                            to_revoke.append(tid)
        return count

    def renew_token(self, token_id: str, ttl: float) -> Token:
        """Extend a token's TTL.

        Args:
            token_id: Token to renew.
            ttl: New TTL in seconds (added to current time).

        Raises:
            AuthenticationError: If token is not renewable.
        """
        with self._lock:
            token = self._tokens.get(token_id)
            if token is None:
                raise AuthenticationError("Invalid token")
            if not token.renewable:
                raise AuthenticationError("Token is not renewable")
            if token.revoked:
                raise AuthenticationError("Token has been revoked")

            token.expires_at = time.time() + ttl
            return token

    def cleanup_expired(self) -> int:
        """Remove expired and revoked tokens. Returns count cleaned."""
        count = 0
        with self._lock:
            expired = [
                tid for tid, t in self._tokens.items()
                if t.expired or t.revoked
            ]
            for tid in expired:
                del self._tokens[tid]
                count += 1
        return count

    # --- App-Role Auth ---

    def create_approle(
        self,
        role_name: str,
        policies: list[str],
        secret_id: Optional[str] = None,
        token_ttl: float = 3600,
    ) -> dict:
        """Create an app-role for machine authentication.

        Returns dict with role_id and secret_id.
        """
        role_id = secrets.token_urlsafe(16)
        if secret_id is None:
            secret_id = secrets.token_urlsafe(32)

        self._approles[role_id] = {
            "role_name": role_name,
            "secret_id": secret_id,
            "policies": policies,
            "token_ttl": token_ttl,
        }
        return {"role_id": role_id, "secret_id": secret_id}

    def approle_login(self, role_id: str, secret_id: str) -> Token:
        """Authenticate with app-role credentials and get a token.

        Raises:
            AuthenticationError: If role_id or secret_id is invalid.
        """
        role = self._approles.get(role_id)
        if role is None:
            raise AuthenticationError("Invalid role_id")

        if not secrets.compare_digest(role["secret_id"], secret_id):
            raise AuthenticationError("Invalid secret_id")

        return self.create_token(
            policies=role["policies"],
            ttl=role["token_ttl"],
            metadata={"auth_method": "approle", "role": role["role_name"]},
        )

    def to_dict(self) -> dict:
        """Serialize token manager state."""
        return {
            "tokens": {
                tid: t.to_dict() for tid, t in self._tokens.items()
            },
            "approles": self._approles,
        }

    def load_from_dict(self, data: dict) -> None:
        """Restore token manager state."""
        for tid, tdata in data.get("tokens", {}).items():
            self._tokens[tid] = Token.from_dict(tdata)
        self._approles = data.get("approles", {})
