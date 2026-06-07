"""Tamper-evident audit logging for VaultLite.

Every vault operation produces an audit entry. Entries form a hash chain:
each entry includes the hash of the previous entry. Tampering with any
entry breaks the chain, making modifications detectable.

The audit log is append-only — entries are never modified or deleted
during normal operation.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Optional

from vaultlite.types import AuditEntry


def _compute_hash(entry_data: str, prev_hash: str) -> str:
    """Compute SHA-256 hash of entry data chained to previous hash."""
    combined = prev_hash + entry_data
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


class AuditLog:
    """Hash-chained audit log for vault operations.

    Every operation (read, write, delete, auth, policy change) is logged
    with actor identity, timestamp, path, and outcome. The hash chain
    ensures tamper detection: modifying any entry invalidates all
    subsequent hashes.

    Example:
        audit = AuditLog()
        audit.log("write", "secret/data/db", actor="token:hvs.abc",
                  outcome="allow", metadata={"version": 3})
    """

    GENESIS_HASH = "0" * 64  # Hash of the "block before the first block"

    def __init__(self):
        self._entries: list[AuditEntry] = []
        self._lock = threading.Lock()

    def log(
        self,
        operation: str,
        path: str = "",
        actor: str = "",
        outcome: str = "allow",
        metadata: Optional[dict] = None,
    ) -> AuditEntry:
        """Append an audit entry to the log.

        Args:
            operation: The operation type (read, write, delete, auth, etc.)
            path: The secret path involved (if any).
            actor: Identity of the actor (token ID or "system").
            outcome: "allow" or "deny".
            metadata: Additional context (version, error message, etc.)

        Returns:
            The new AuditEntry with computed hash.
        """
        with self._lock:
            prev_hash = (
                self._entries[-1].entry_hash
                if self._entries
                else self.GENESIS_HASH
            )

            entry = AuditEntry(
                timestamp=time.time(),
                operation=operation,
                path=path,
                actor=actor,
                outcome=outcome,
                metadata=metadata or {},
                prev_hash=prev_hash,
            )

            # Compute hash of this entry's content
            content = json.dumps({
                "timestamp": entry.timestamp,
                "operation": entry.operation,
                "path": entry.path,
                "actor": entry.actor,
                "outcome": entry.outcome,
                "metadata": entry.metadata,
            }, sort_keys=True)
            entry.entry_hash = _compute_hash(content, prev_hash)

            self._entries.append(entry)
            return entry

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Verify the integrity of the entire hash chain.

        Returns:
            (valid, broken_at): valid is True if chain is intact.
            If broken, broken_at is the index of the first invalid entry.
        """
        with self._lock:
            prev_hash = self.GENESIS_HASH

            for i, entry in enumerate(self._entries):
                if entry.prev_hash != prev_hash:
                    return False, i

                content = json.dumps({
                    "timestamp": entry.timestamp,
                    "operation": entry.operation,
                    "path": entry.path,
                    "actor": entry.actor,
                    "outcome": entry.outcome,
                    "metadata": entry.metadata,
                }, sort_keys=True)
                expected = _compute_hash(content, prev_hash)

                if entry.entry_hash != expected:
                    return False, i

                prev_hash = entry.entry_hash

            return True, None

    def query(
        self,
        operation: Optional[str] = None,
        path: Optional[str] = None,
        actor: Optional[str] = None,
        outcome: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries with filters.

        All filters are optional — unset filters match everything.
        Results are returned in reverse chronological order (newest first).
        """
        with self._lock:
            results = []
            for entry in reversed(self._entries):
                if operation and entry.operation != operation:
                    continue
                if path and not entry.path.startswith(path):
                    continue
                if actor and entry.actor != actor:
                    continue
                if outcome and entry.outcome != outcome:
                    continue
                if since and entry.timestamp < since:
                    continue
                if until and entry.timestamp > until:
                    continue
                results.append(entry)
                if len(results) >= limit:
                    break
            return results

    @property
    def entry_count(self) -> int:
        """Number of entries in the log."""
        with self._lock:
            return len(self._entries)

    def get_entries(self, last_n: int = 50) -> list[AuditEntry]:
        """Get the most recent N entries."""
        with self._lock:
            return list(self._entries[-last_n:])

    def to_list(self) -> list[dict]:
        """Serialize the full log."""
        with self._lock:
            return [e.to_dict() for e in self._entries]

    def load_from_list(self, data: list[dict]) -> None:
        """Restore audit log from serialized data."""
        with self._lock:
            self._entries = [AuditEntry.from_dict(d) for d in data]

    def clear(self) -> None:
        """Clear the audit log (for testing only)."""
        with self._lock:
            self._entries.clear()
