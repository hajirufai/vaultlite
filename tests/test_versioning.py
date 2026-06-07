"""Tests for secret versioning."""

import unittest

from vaultlite.versioning import VersionedSecret
from vaultlite.errors import VersionNotFoundError


class TestVersionedSecret(unittest.TestCase):

    def setUp(self):
        self.vs = VersionedSecret("secret/db")

    def test_write_creates_version(self):
        v = self.vs.write({"password": "v1"})
        self.assertEqual(v.version, 1)
        self.assertEqual(v.data, {"password": "v1"})

    def test_write_increments_version(self):
        self.vs.write({"v": 1})
        v2 = self.vs.write({"v": 2})
        self.assertEqual(v2.version, 2)

    def test_read_current(self):
        self.vs.write({"v": 1})
        self.vs.write({"v": 2})
        current = self.vs.read()
        self.assertEqual(current.version, 2)
        self.assertEqual(current.data, {"v": 2})

    def test_read_specific_version(self):
        self.vs.write({"v": 1})
        self.vs.write({"v": 2})
        v1 = self.vs.read(version=1)
        self.assertEqual(v1.data, {"v": 1})

    def test_read_nonexistent_version(self):
        self.vs.write({"v": 1})
        with self.assertRaises(VersionNotFoundError):
            self.vs.read(version=99)

    def test_read_empty_secret(self):
        with self.assertRaises(VersionNotFoundError):
            self.vs.read()

    def test_soft_delete(self):
        self.vs.write({"v": 1})
        sv = self.vs.soft_delete()
        self.assertTrue(sv.deleted)
        self.assertIsNotNone(sv.deleted_at)

    def test_soft_delete_specific_version(self):
        self.vs.write({"v": 1})
        self.vs.write({"v": 2})
        self.vs.soft_delete(version=1)
        # Version 2 should still be current
        current = self.vs.read()
        self.assertEqual(current.version, 2)

    def test_soft_delete_all_hides_secret(self):
        self.vs.write({"v": 1})
        self.vs.soft_delete()
        with self.assertRaises(VersionNotFoundError):
            self.vs.read()

    def test_undelete(self):
        self.vs.write({"v": 1})
        self.vs.soft_delete()
        self.vs.undelete(1)
        current = self.vs.read()
        self.assertEqual(current.data, {"v": 1})
        self.assertFalse(current.deleted)

    def test_undelete_nonexistent(self):
        with self.assertRaises(VersionNotFoundError):
            self.vs.undelete(99)

    def test_destroy(self):
        self.vs.write({"v": 1})
        self.vs.destroy(1)
        with self.assertRaises(VersionNotFoundError):
            self.vs.read(version=1)

    def test_destroy_nonexistent(self):
        with self.assertRaises(VersionNotFoundError):
            self.vs.destroy(99)

    def test_destroy_erases_data(self):
        self.vs.write({"password": "sensitive"})
        self.vs.destroy(1)
        # The version still exists in history but data is empty
        history = self.vs.history()
        self.assertEqual(len(history), 1)
        self.assertTrue(history[0]["destroyed"])

    def test_history(self):
        self.vs.write({"v": 1})
        self.vs.write({"v": 2})
        h = self.vs.history()
        self.assertEqual(len(h), 2)
        self.assertEqual(h[0]["version"], 1)
        self.assertEqual(h[1]["version"], 2)
        self.assertNotIn("data", h[0])  # History shouldn't expose data

    def test_max_versions_pruning(self):
        vs = VersionedSecret("test", max_versions=3)
        for i in range(5):
            vs.write({"v": i})
        # Should only keep last 3
        self.assertEqual(len(vs._versions), 3)
        self.assertEqual(vs._versions[0].version, 3)
        self.assertEqual(vs._versions[-1].version, 5)

    def test_latest_version_number(self):
        self.assertEqual(self.vs.latest_version_number, 0)
        self.vs.write({"v": 1})
        self.assertEqual(self.vs.latest_version_number, 1)
        self.vs.write({"v": 2})
        self.assertEqual(self.vs.latest_version_number, 2)

    def test_serialization_round_trip(self):
        self.vs.write({"v": 1})
        self.vs.write({"v": 2})
        self.vs.soft_delete(version=1)

        data = self.vs.to_dict()
        restored = VersionedSecret.from_dict(data)

        self.assertEqual(restored.path, self.vs.path)
        self.assertEqual(len(restored._versions), 2)
        self.assertTrue(restored._versions[0].deleted)


if __name__ == "__main__":
    unittest.main()
