"""Secret versioning — track history, rollback, soft-delete.

Every write to a secret path creates a new version. Old versions
are preserved for audit and rollback. Versions can be soft-deleted
(marked as deleted but recoverable) or destroyed (permanently erased).

Design mirrors HashiCorp Vault's KV v2 secrets engine.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from vaultlite.types import SecretVersion
from vaultlite.errors import VersionNotFoundError


class VersionedSecret:
    """A secret with version history.

    Maintains an ordered list of versions. The "current" version is
    the latest non-destroyed, non-deleted version.
    """

    def __init__(self, path: str, max_versions: int = 10):
        self.path = path
        self.max_versions = max_versions
        self._versions: list[SecretVersion] = []
        self._next_version = 1

    @property
    def current_version(self) -> Optional[SecretVersion]:
        """Get the latest active (non-deleted, non-destroyed) version."""
        for v in reversed(self._versions):
            if not v.destroyed and not v.deleted:
                return v
        return None

    @property
    def latest_version_number(self) -> int:
        """The highest version number that exists."""
        if not self._versions:
            return 0
        return self._versions[-1].version

    def write(self, data: dict[str, Any], created_by: str = "") -> SecretVersion:
        """Create a new version with the given data.

        If max_versions is exceeded, the oldest version is destroyed.
        """
        version = SecretVersion(
            version=self._next_version,
            data=data,
            created_at=time.time(),
            created_by=created_by,
        )
        self._next_version += 1
        self._versions.append(version)

        # Prune oldest versions beyond max
        while len(self._versions) > self.max_versions:
            self._versions[0].destroyed = True
            self._versions[0].data = {}
            self._versions.pop(0)

        return version

    def read(self, version: Optional[int] = None) -> SecretVersion:
        """Read a specific version or the current version.

        Args:
            version: Version number to read. None = current.

        Raises:
            VersionNotFoundError: If the version doesn't exist or is destroyed.
        """
        if version is None:
            current = self.current_version
            if current is None:
                raise VersionNotFoundError(self.path, 0)
            return current

        for v in self._versions:
            if v.version == version:
                if v.destroyed:
                    raise VersionNotFoundError(self.path, version)
                return v

        raise VersionNotFoundError(self.path, version)

    def soft_delete(self, version: Optional[int] = None) -> SecretVersion:
        """Mark a version as deleted (recoverable).

        Args:
            version: Version to delete. None = latest.

        Raises:
            VersionNotFoundError: If the version doesn't exist.
        """
        v = self.read(version)
        v.deleted = True
        v.deleted_at = time.time()
        return v

    def undelete(self, version: int) -> SecretVersion:
        """Restore a soft-deleted version.

        Raises:
            VersionNotFoundError: If the version doesn't exist.
        """
        for v in self._versions:
            if v.version == version:
                if v.destroyed:
                    raise VersionNotFoundError(self.path, version)
                v.deleted = False
                v.deleted_at = None
                return v
        raise VersionNotFoundError(self.path, version)

    def destroy(self, version: int) -> None:
        """Permanently destroy a version (no recovery).

        The version entry remains but its data is erased.
        """
        for v in self._versions:
            if v.version == version:
                v.destroyed = True
                v.data = {}
                v.deleted = True
                v.deleted_at = time.time()
                return
        raise VersionNotFoundError(self.path, version)

    def history(self) -> list[dict]:
        """Get version history metadata (without data)."""
        return [
            {
                "version": v.version,
                "created_at": v.created_at,
                "created_by": v.created_by,
                "deleted": v.deleted,
                "destroyed": v.destroyed,
            }
            for v in self._versions
        ]

    def to_dict(self) -> dict:
        """Serialize the versioned secret."""
        return {
            "path": self.path,
            "max_versions": self.max_versions,
            "next_version": self._next_version,
            "versions": [v.to_dict() for v in self._versions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VersionedSecret":
        """Deserialize a versioned secret."""
        vs = cls(path=data["path"], max_versions=data.get("max_versions", 10))
        vs._next_version = data.get("next_version", 1)
        vs._versions = [
            SecretVersion.from_dict(v) for v in data.get("versions", [])
        ]
        return vs
