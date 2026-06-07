"""Core data types for VaultLite."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Secret:
    """A stored secret with metadata."""

    path: str
    data: dict[str, Any]
    version: int = 1
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    deleted: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "data": self.data,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "deleted": self.deleted,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Secret":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class SecretVersion:
    """A single version of a secret's data."""

    version: int
    data: dict[str, Any]
    created_at: float = field(default_factory=time.time)
    created_by: str = ""
    deleted: bool = False
    deleted_at: Optional[float] = None
    destroyed: bool = False

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "data": self.data,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "deleted": self.deleted,
            "deleted_at": self.deleted_at,
            "destroyed": self.destroyed,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SecretVersion":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Rule:
    """A single access rule: path pattern + capabilities."""

    path: str
    capabilities: list[str] = field(default_factory=list)

    VALID_CAPABILITIES = {"read", "write", "delete", "list", "sudo"}

    def to_dict(self) -> dict:
        return {"path": self.path, "capabilities": self.capabilities}

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(path=d["path"], capabilities=d.get("capabilities", []))


@dataclass
class Policy:
    """An access control policy with named rules."""

    name: str
    rules: list[Rule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "rules": [r.to_dict() for r in self.rules],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        rules = [Rule.from_dict(r) for r in d.get("rules", [])]
        return cls(name=d["name"], rules=rules)


@dataclass
class Token:
    """An authentication token with policies and TTL."""

    token_id: str
    policies: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    renewable: bool = True
    max_uses: int = 0  # 0 = unlimited
    use_count: int = 0
    parent_token: Optional[str] = None
    metadata: dict[str, str] = field(default_factory=dict)
    revoked: bool = False
    is_root: bool = False

    @property
    def expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def uses_exhausted(self) -> bool:
        if self.max_uses == 0:
            return False
        return self.use_count >= self.max_uses

    def to_dict(self) -> dict:
        return {
            "token_id": self.token_id,
            "policies": self.policies,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "renewable": self.renewable,
            "max_uses": self.max_uses,
            "use_count": self.use_count,
            "parent_token": self.parent_token,
            "metadata": self.metadata,
            "revoked": self.revoked,
            "is_root": self.is_root,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Token":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Lease:
    """A lease on a secret — tracks TTL and renewal."""

    lease_id: str
    secret_path: str
    token_id: str
    ttl: float  # seconds
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    renewable: bool = True
    revoked: bool = False
    max_ttl: float = 86400.0  # 24 hours default max

    def __post_init__(self):
        if self.expires_at == 0.0:
            self.expires_at = self.created_at + self.ttl

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def remaining(self) -> float:
        return max(0, self.expires_at - time.time())

    def to_dict(self) -> dict:
        return {
            "lease_id": self.lease_id,
            "secret_path": self.secret_path,
            "token_id": self.token_id,
            "ttl": self.ttl,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "renewable": self.renewable,
            "revoked": self.revoked,
            "max_ttl": self.max_ttl,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Lease":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class AuditEntry:
    """An entry in the audit log."""

    timestamp: float = field(default_factory=time.time)
    operation: str = ""
    path: str = ""
    actor: str = ""
    outcome: str = "allow"  # allow or deny
    metadata: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "operation": self.operation,
            "path": self.path,
            "actor": self.actor,
            "outcome": self.outcome,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEntry":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class SealStatus:
    """Current seal state of the vault."""

    sealed: bool = True
    initialized: bool = False
    threshold: int = 0
    total_shares: int = 0
    progress: int = 0  # number of unseal shares provided so far

    def to_dict(self) -> dict:
        return {
            "sealed": self.sealed,
            "initialized": self.initialized,
            "threshold": self.threshold,
            "total_shares": self.total_shares,
            "progress": self.progress,
        }


@dataclass
class EncryptedPayload:
    """An encrypted piece of data with all necessary components."""

    ciphertext: str  # base64-encoded
    iv: str  # base64-encoded
    hmac: str  # hex-encoded
    encrypted_dek: str  # base64-encoded (envelope encryption)
    kdf_salt: str = ""  # base64-encoded (if KDF was used)
    kdf_iterations: int = 100000

    def to_dict(self) -> dict:
        return {
            "ciphertext": self.ciphertext,
            "iv": self.iv,
            "hmac": self.hmac,
            "encrypted_dek": self.encrypted_dek,
            "kdf_salt": self.kdf_salt,
            "kdf_iterations": self.kdf_iterations,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "EncryptedPayload":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class InitResult:
    """Result of vault initialization."""

    root_token: str
    unseal_keys: list[str]
    threshold: int
    total_shares: int
