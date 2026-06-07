"""VaultLite — the central secrets manager.

Orchestrates all subsystems: crypto, storage, auth, policies,
auditing, leasing, versioning, and seal/unseal. Every operation
flows through this class.

Usage:
    vault = Vault()
    result = vault.initialize(shares=5, threshold=3)
    vault.unseal(result.unseal_keys[0])
    vault.unseal(result.unseal_keys[1])
    vault.unseal(result.unseal_keys[2])  # Unsealed!

    vault.write("secret/data/db", {"password": "hunter2"}, token=result.root_token)
    secret = vault.read("secret/data/db", token=result.root_token)
"""

from __future__ import annotations

import json
from typing import Any, Optional

from vaultlite.audit import AuditLog
from vaultlite.auth import TokenManager
from vaultlite.crypto.envelope import EnvelopeEncryption
from vaultlite.errors import (
    AuthenticationError,
    AuthorizationError,
    CryptoError,
    InitializationError,
    SecretNotFoundError,
    SealedError,
    VersionNotFoundError,
)
from vaultlite.lease import LeaseManager
from vaultlite.policy import PolicyManager
from vaultlite.seal import SealManager
from vaultlite.store import MemoryStore, Store
from vaultlite.types import (
    AuditEntry,
    InitResult,
    Lease,
    Policy,
    SealStatus,
    Secret,
    Token,
)
from vaultlite.utils import sanitize_path
from vaultlite.versioning import VersionedSecret


class Vault:
    """The VaultLite secrets manager.

    Coordinates encryption, storage, authentication, authorization,
    auditing, leasing, and versioning into a unified API.

    All data is encrypted at rest using envelope encryption. The master
    key is protected by the seal mechanism. Access is controlled by
    token-based authentication and path-based policies.
    """

    def __init__(self, store: Optional[Store] = None):
        """Initialize the vault.

        Args:
            store: Storage backend. Defaults to MemoryStore.
        """
        self._store = store or MemoryStore()
        self._seal = SealManager()
        self._auth = TokenManager()
        self._policies = PolicyManager()
        self._audit = AuditLog()
        self._leases = LeaseManager()
        self._secrets: dict[str, VersionedSecret] = {}
        self._envelope: Optional[EnvelopeEncryption] = None
        self._root_token: Optional[str] = None

    # --- Lifecycle ---

    def initialize(
        self, shares: int = 5, threshold: int = 5
    ) -> InitResult:
        """Initialize the vault with a new master key.

        Generates the master key, splits it into shares, and creates
        a root token. Must be called exactly once.

        Args:
            shares: Number of unseal key shares.
            threshold: Minimum shares to unseal.

        Returns:
            InitResult with root_token and unseal_keys.
        """
        result = self._seal.initialize(shares, threshold)

        # Create root token in auth system
        root_token = self._auth.create_root_token()
        result = InitResult(
            root_token=root_token.token_id,
            unseal_keys=result.unseal_keys,
            threshold=result.threshold,
            total_shares=result.total_shares,
        )
        self._root_token = root_token.token_id

        self._audit.log(
            operation="init",
            actor="system",
            metadata={"shares": shares, "threshold": threshold},
        )
        return result

    def unseal(self, share: str) -> SealStatus:
        """Provide an unseal share.

        Call multiple times with different shares. When enough shares
        reach the threshold, the vault unseals.
        """
        status = self._seal.provide_unseal_share(share)

        if not status.sealed:
            # Vault just unsealed — initialize encryption
            master_key = self._seal.master_key
            if master_key:
                self._envelope = EnvelopeEncryption(master_key)

            self._audit.log(
                operation="unseal",
                actor="system",
                outcome="allow",
                metadata={"sealed": False},
            )
        else:
            self._audit.log(
                operation="unseal",
                actor="system",
                metadata={"progress": status.progress, "threshold": status.threshold},
            )

        return status

    def seal(self) -> SealStatus:
        """Seal the vault — forget the master key."""
        status = self._seal.seal()
        self._envelope = None
        self._audit.log(operation="seal", actor="system")
        return status

    @property
    def seal_status(self) -> SealStatus:
        """Current seal status."""
        return self._seal.status

    def _require_unsealed(self) -> EnvelopeEncryption:
        """Assert vault is unsealed and return envelope encryption."""
        self._seal.require_unsealed()
        if self._envelope is None:
            raise SealedError("Encryption not available")
        return self._envelope

    def _authenticate(self, token_id: str) -> Token:
        """Validate a token."""
        return self._auth.validate_token(token_id)

    def _authorize(self, token: Token, path: str, capability: str) -> None:
        """Check authorization. Raises AuthorizationError if denied."""
        if token.is_root:
            return  # Root tokens bypass policy checks

        if not self._policies.check_access(token.policies, path, capability):
            self._audit.log(
                operation=capability,
                path=path,
                actor=token.token_id[:12] + "...",
                outcome="deny",
            )
            raise AuthorizationError(
                f"Token lacks '{capability}' capability on path '{path}'"
            )

    # --- Secret Operations ---

    def write(
        self,
        path: str,
        data: dict[str, Any],
        token: str,
    ) -> dict:
        """Write a secret (creates a new version).

        Args:
            path: Secret path (e.g., "secret/data/db").
            data: Key-value pairs to store.
            token: Authentication token.

        Returns:
            Dict with version info and lease_id.
        """
        envelope = self._require_unsealed()
        tok = self._authenticate(token)
        path = sanitize_path(path)
        self._authorize(tok, path, "write")

        # Get or create versioned secret
        if path not in self._secrets:
            self._secrets[path] = VersionedSecret(path)

        vs = self._secrets[path]
        actor_id = tok.token_id[:12] + "..."
        version = vs.write(data, created_by=actor_id)

        # Encrypt and store the version data
        plaintext = json.dumps(data).encode("utf-8")
        payload = envelope.encrypt(plaintext)
        self._store.put(
            f"secrets/{path}/v{version.version}",
            payload.to_dict(),
        )

        # Store version metadata
        self._store.put(f"secrets/{path}/_meta", vs.to_dict())

        self._audit.log(
            operation="write",
            path=path,
            actor=actor_id,
            outcome="allow",
            metadata={"version": version.version},
        )

        return {
            "path": path,
            "version": version.version,
            "created_at": version.created_at,
        }

    def read(
        self,
        path: str,
        token: str,
        version: Optional[int] = None,
    ) -> dict:
        """Read a secret.

        Args:
            path: Secret path.
            token: Authentication token.
            version: Specific version to read. None = latest.

        Returns:
            Dict with secret data and metadata.
        """
        envelope = self._require_unsealed()
        tok = self._authenticate(token)
        path = sanitize_path(path)
        self._authorize(tok, path, "read")

        if path not in self._secrets:
            raise SecretNotFoundError(path)

        vs = self._secrets[path]
        try:
            sv = vs.read(version)
        except VersionNotFoundError:
            raise SecretNotFoundError(path)

        if sv.deleted:
            raise SecretNotFoundError(path)

        # Decrypt the stored data
        stored = self._store.get(f"secrets/{path}/v{sv.version}")
        if stored is None:
            raise SecretNotFoundError(path)

        from vaultlite.types import EncryptedPayload

        payload = EncryptedPayload.from_dict(stored)
        plaintext = envelope.decrypt(payload)
        data = json.loads(plaintext.decode("utf-8"))

        actor_id = tok.token_id[:12] + "..."

        # Create a lease for this read
        lease = self._leases.create_lease(
            secret_path=path,
            token_id=tok.token_id,
        )

        self._audit.log(
            operation="read",
            path=path,
            actor=actor_id,
            outcome="allow",
            metadata={"version": sv.version, "lease_id": lease.lease_id},
        )

        return {
            "path": path,
            "data": data,
            "version": sv.version,
            "created_at": sv.created_at,
            "lease_id": lease.lease_id,
            "lease_duration": lease.ttl,
        }

    def delete(self, path: str, token: str, version: Optional[int] = None) -> dict:
        """Soft-delete a secret version.

        Args:
            path: Secret path.
            token: Authentication token.
            version: Version to delete. None = latest.

        Returns:
            Dict confirming deletion.
        """
        self._require_unsealed()
        tok = self._authenticate(token)
        path = sanitize_path(path)
        self._authorize(tok, path, "delete")

        if path not in self._secrets:
            raise SecretNotFoundError(path)

        vs = self._secrets[path]
        sv = vs.soft_delete(version)
        self._store.put(f"secrets/{path}/_meta", vs.to_dict())

        actor_id = tok.token_id[:12] + "..."
        self._audit.log(
            operation="delete",
            path=path,
            actor=actor_id,
            outcome="allow",
            metadata={"version": sv.version},
        )

        return {"path": path, "version": sv.version, "deleted": True}

    def undelete(self, path: str, token: str, version: int) -> dict:
        """Restore a soft-deleted version."""
        self._require_unsealed()
        tok = self._authenticate(token)
        path = sanitize_path(path)
        self._authorize(tok, path, "write")

        if path not in self._secrets:
            raise SecretNotFoundError(path)

        vs = self._secrets[path]
        sv = vs.undelete(version)
        self._store.put(f"secrets/{path}/_meta", vs.to_dict())

        actor_id = tok.token_id[:12] + "..."
        self._audit.log(
            operation="undelete",
            path=path,
            actor=actor_id,
            outcome="allow",
            metadata={"version": sv.version},
        )

        return {"path": path, "version": sv.version, "deleted": False}

    def destroy(self, path: str, token: str, version: int) -> dict:
        """Permanently destroy a version (no recovery)."""
        self._require_unsealed()
        tok = self._authenticate(token)
        path = sanitize_path(path)
        self._authorize(tok, path, "delete")

        if path not in self._secrets:
            raise SecretNotFoundError(path)

        vs = self._secrets[path]
        vs.destroy(version)

        # Remove encrypted data from store
        self._store.delete(f"secrets/{path}/v{version}")
        self._store.put(f"secrets/{path}/_meta", vs.to_dict())

        actor_id = tok.token_id[:12] + "..."
        self._audit.log(
            operation="destroy",
            path=path,
            actor=actor_id,
            outcome="allow",
            metadata={"version": version},
        )

        return {"path": path, "version": version, "destroyed": True}

    def list_secrets(self, path: str, token: str) -> list[str]:
        """List secret paths under a prefix.

        Args:
            path: Path prefix (e.g., "secret/data/").
            token: Authentication token.

        Returns:
            List of secret paths matching the prefix.
        """
        self._require_unsealed()
        tok = self._authenticate(token)
        path = sanitize_path(path)
        self._authorize(tok, path, "list")

        prefix = path if path.endswith("/") else path + "/"
        results = [
            p for p in self._secrets
            if p.startswith(prefix) or p == path.rstrip("/")
        ]

        actor_id = tok.token_id[:12] + "..."
        self._audit.log(
            operation="list",
            path=path,
            actor=actor_id,
            outcome="allow",
            metadata={"count": len(results)},
        )

        return sorted(results)

    def metadata(self, path: str, token: str) -> dict:
        """Get secret metadata including version history."""
        self._require_unsealed()
        tok = self._authenticate(token)
        path = sanitize_path(path)
        self._authorize(tok, path, "read")

        if path not in self._secrets:
            raise SecretNotFoundError(path)

        vs = self._secrets[path]
        return {
            "path": path,
            "current_version": vs.latest_version_number,
            "versions": vs.history(),
        }

    # --- Policy Operations ---

    def put_policy(self, name: str, policy: Policy, token: str) -> dict:
        """Create or update an access policy."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, f"sys/policy/{name}", "write")

        self._policies.add_policy(policy)

        self._audit.log(
            operation="policy_write",
            path=f"sys/policy/{name}",
            actor=tok.token_id[:12] + "...",
            outcome="allow",
        )

        return {"name": name, "rules": len(policy.rules)}

    def get_policy(self, name: str, token: str) -> Optional[Policy]:
        """Get a policy by name."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, f"sys/policy/{name}", "read")
        return self._policies.get_policy(name)

    def delete_policy(self, name: str, token: str) -> bool:
        """Delete a policy."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, f"sys/policy/{name}", "delete")

        result = self._policies.delete_policy(name)

        self._audit.log(
            operation="policy_delete",
            path=f"sys/policy/{name}",
            actor=tok.token_id[:12] + "...",
            outcome="allow",
        )

        return result

    def list_policies(self, token: str) -> list[str]:
        """List all policy names."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, "sys/policy", "list")
        return self._policies.list_policies()

    # --- Token Operations ---

    def create_token(
        self,
        token: str,
        policies: Optional[list[str]] = None,
        ttl: Optional[float] = None,
        renewable: bool = True,
        max_uses: int = 0,
        metadata: Optional[dict] = None,
    ) -> Token:
        """Create a child token."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, "auth/token/create", "write")

        child = self._auth.create_token(
            policies=policies or ["default"],
            parent_token=tok.token_id,
            ttl=ttl,
            renewable=renewable,
            max_uses=max_uses,
            metadata=metadata,
        )

        self._audit.log(
            operation="token_create",
            actor=tok.token_id[:12] + "...",
            outcome="allow",
            metadata={"child_token": child.token_id[:12] + "..."},
        )

        return child

    def revoke_token(self, token: str, target_token: str) -> int:
        """Revoke a token and its children."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, "auth/token/revoke", "write")

        count = self._auth.revoke_token(target_token)

        # Also revoke associated leases
        self._leases.revoke_by_token(target_token)

        self._audit.log(
            operation="token_revoke",
            actor=tok.token_id[:12] + "...",
            outcome="allow",
            metadata={"revoked_count": count},
        )

        return count

    def lookup_token(self, token: str, target_token: Optional[str] = None) -> dict:
        """Look up token info."""
        self._require_unsealed()
        tok = self._authenticate(token)

        target = target_token or tok.token_id
        info = self._auth.lookup_token(target)
        if info is None:
            raise AuthenticationError("Token not found")

        return {
            "token_id": info.token_id[:12] + "...",
            "policies": info.policies,
            "created_at": info.created_at,
            "expires_at": info.expires_at,
            "renewable": info.renewable,
            "is_root": info.is_root,
        }

    # --- Lease Operations ---

    def renew_lease(self, token: str, lease_id: str, ttl: Optional[float] = None) -> Lease:
        """Renew a lease."""
        self._require_unsealed()
        self._authenticate(token)
        return self._leases.renew_lease(lease_id, ttl)

    def revoke_lease(self, token: str, lease_id: str) -> bool:
        """Revoke a lease."""
        self._require_unsealed()
        self._authenticate(token)
        return self._leases.revoke_lease(lease_id)

    # --- Audit Operations ---

    def audit_log(
        self,
        token: str,
        limit: int = 50,
        operation: Optional[str] = None,
        path: Optional[str] = None,
    ) -> list[dict]:
        """Query the audit log."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, "sys/audit", "read")

        entries = self._audit.query(
            operation=operation,
            path=path,
            limit=limit,
        )

        return [e.to_dict() for e in entries]

    def verify_audit_chain(self, token: str) -> dict:
        """Verify audit log integrity."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, "sys/audit", "read")

        valid, broken_at = self._audit.verify_chain()
        return {
            "valid": valid,
            "broken_at": broken_at,
            "total_entries": self._audit.entry_count,
        }

    # --- App-Role Auth ---

    def create_approle(
        self,
        token: str,
        role_name: str,
        policies: list[str],
        token_ttl: float = 3600,
    ) -> dict:
        """Create an app-role for machine authentication."""
        self._require_unsealed()
        tok = self._authenticate(token)
        self._authorize(tok, "auth/approle", "write")

        result = self._auth.create_approle(
            role_name=role_name,
            policies=policies,
            token_ttl=token_ttl,
        )

        self._audit.log(
            operation="approle_create",
            actor=tok.token_id[:12] + "...",
            outcome="allow",
            metadata={"role": role_name},
        )

        return result

    def approle_login(self, role_id: str, secret_id: str) -> dict:
        """Login with app-role credentials."""
        token = self._auth.approle_login(role_id, secret_id)

        self._audit.log(
            operation="approle_login",
            actor=token.token_id[:12] + "...",
            outcome="allow",
        )

        return {
            "token": token.token_id,
            "policies": token.policies,
            "expires_at": token.expires_at,
        }

    # --- Health ---

    def health(self) -> dict:
        """Health check — doesn't require authentication."""
        return {
            "initialized": self._seal.status.initialized,
            "sealed": self._seal.status.sealed,
            "version": "1.0.0",
        }
