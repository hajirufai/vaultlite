"""Storage backends for VaultLite.

All backends store encrypted data — the store never sees plaintext.
Three implementations:
- MemoryStore: dict-based, fast, no persistence (testing)
- FileStore: JSON files on disk, one directory per path prefix
- SQLiteStore: SQLite database, single file, ACID transactions
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional


class Store(ABC):
    """Abstract storage backend interface."""

    @abstractmethod
    def get(self, key: str) -> Optional[dict]:
        """Retrieve a value by key. Returns None if not found."""
        ...

    @abstractmethod
    def put(self, key: str, value: dict) -> None:
        """Store a value by key. Overwrites if exists."""
        ...

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a key. Returns True if it existed."""
        ...

    @abstractmethod
    def list_keys(self, prefix: str = "") -> list[str]:
        """List all keys matching a prefix."""
        ...

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if a key exists."""
        ...

    def close(self) -> None:
        """Clean up resources (optional)."""
        pass


class MemoryStore(Store):
    """In-memory storage backend using a plain dict.

    Fast and simple, but all data is lost when the process exits.
    Ideal for testing and development.
    """

    def __init__(self):
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            stored = self._data.get(key)
            return json.loads(json.dumps(stored)) if stored else None

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._data[key] = json.loads(json.dumps(value))

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    def list_keys(self, prefix: str = "") -> list[str]:
        with self._lock:
            return sorted(k for k in self._data if k.startswith(prefix))

    def exists(self, key: str) -> bool:
        with self._lock:
            return key in self._data


class FileStore(Store):
    """File-based storage backend. Each key maps to a JSON file.

    Keys are mapped to file paths: "secret/data/db" becomes
    "<root>/secret/data/db.json". Directory structure is created
    automatically.
    """

    def __init__(self, root: str | Path):
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _key_to_path(self, key: str) -> Path:
        safe = key.replace("../", "").strip("/")
        return self._root / f"{safe}.json"

    def get(self, key: str) -> Optional[dict]:
        path = self._key_to_path(key)
        with self._lock:
            if not path.exists():
                return None
            return json.loads(path.read_text(encoding="utf-8"))

    def put(self, key: str, value: dict) -> None:
        path = self._key_to_path(key)
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(value, indent=2), encoding="utf-8"
            )

    def delete(self, key: str) -> bool:
        path = self._key_to_path(key)
        with self._lock:
            if path.exists():
                path.unlink()
                return True
            return False

    def list_keys(self, prefix: str = "") -> list[str]:
        with self._lock:
            keys = []
            prefix_path = self._root / prefix.replace("../", "").strip("/")
            search_dir = prefix_path if prefix_path.is_dir() else prefix_path.parent
            if not search_dir.exists():
                return []
            for f in search_dir.rglob("*.json"):
                rel = f.relative_to(self._root)
                key = str(rel).replace(".json", "").replace(os.sep, "/")
                if key.startswith(prefix):
                    keys.append(key)
            return sorted(keys)

    def exists(self, key: str) -> bool:
        return self._key_to_path(key).exists()


class SQLiteStore(Store):
    """SQLite-based storage backend. All data in one file.

    Uses a single `kv` table with TEXT key and JSON value columns.
    Thread-safe via WAL mode and Python threading lock.
    """

    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS kv "
            "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        self._conn.commit()

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            )
            row = cur.fetchone()
            return json.loads(row[0]) if row else None

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
                (key, json.dumps(value)),
            )
            self._conn.commit()

    def delete(self, key: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            self._conn.commit()
            return cur.rowcount > 0

    def list_keys(self, prefix: str = "") -> list[str]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT key FROM kv WHERE key LIKE ? ORDER BY key",
                (prefix + "%",),
            )
            return [row[0] for row in cur.fetchall()]

    def exists(self, key: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM kv WHERE key = ?", (key,)
            )
            return cur.fetchone() is not None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
