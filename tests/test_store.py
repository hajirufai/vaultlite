"""Tests for storage backends."""

import os
import tempfile
import unittest

from vaultlite.store import MemoryStore, FileStore, SQLiteStore


class StoreTestMixin:
    """Shared tests for all storage backends."""

    store = None  # Set by subclass

    def test_put_and_get(self):
        self.store.put("key1", {"value": "hello"})
        result = self.store.get("key1")
        self.assertEqual(result, {"value": "hello"})

    def test_get_missing(self):
        self.assertIsNone(self.store.get("nonexistent"))

    def test_put_overwrites(self):
        self.store.put("key1", {"v": 1})
        self.store.put("key1", {"v": 2})
        self.assertEqual(self.store.get("key1"), {"v": 2})

    def test_delete_existing(self):
        self.store.put("key1", {"v": 1})
        self.assertTrue(self.store.delete("key1"))
        self.assertIsNone(self.store.get("key1"))

    def test_delete_missing(self):
        self.assertFalse(self.store.delete("nonexistent"))

    def test_exists(self):
        self.assertFalse(self.store.exists("key1"))
        self.store.put("key1", {"v": 1})
        self.assertTrue(self.store.exists("key1"))

    def test_list_keys(self):
        self.store.put("secret/a", {"v": 1})
        self.store.put("secret/b", {"v": 2})
        self.store.put("other/c", {"v": 3})
        keys = self.store.list_keys("secret/")
        self.assertIn("secret/a", keys)
        self.assertIn("secret/b", keys)
        self.assertNotIn("other/c", keys)

    def test_list_keys_empty(self):
        keys = self.store.list_keys("nothing/")
        self.assertEqual(keys, [])

    def test_complex_value(self):
        data = {
            "nested": {"key": "value"},
            "list": [1, 2, 3],
            "number": 42,
            "null": None,
            "bool": True,
        }
        self.store.put("complex", data)
        self.assertEqual(self.store.get("complex"), data)

    def test_isolation(self):
        """Modifying returned data shouldn't affect stored data."""
        self.store.put("key1", {"v": [1, 2]})
        result = self.store.get("key1")
        result["v"].append(3)
        self.assertEqual(self.store.get("key1"), {"v": [1, 2]})


class TestMemoryStore(StoreTestMixin, unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()


class TestFileStore(StoreTestMixin, unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = FileStore(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)


class TestSQLiteStore(StoreTestMixin, unittest.TestCase):
    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmpfile.close()
        self.store = SQLiteStore(self.tmpfile.name)

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmpfile.name)


if __name__ == "__main__":
    unittest.main()
