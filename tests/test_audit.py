"""Tests for hash-chained audit logging."""

import unittest
import time

from vaultlite.audit import AuditLog


class TestAuditLog(unittest.TestCase):

    def setUp(self):
        self.audit = AuditLog()

    def test_log_entry(self):
        self.audit.log(
            operation="read",
            path="secret/db",
            actor="user1",
            outcome="allow",
        )
        self.assertEqual(self.audit.entry_count, 1)

    def test_log_multiple(self):
        for i in range(10):
            self.audit.log(operation=f"op{i}", actor="user")
        self.assertEqual(self.audit.entry_count, 10)

    def test_chain_valid(self):
        for i in range(5):
            self.audit.log(operation=f"op{i}", actor="user")
        valid, broken_at = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(broken_at)

    def test_chain_detects_tampering(self):
        for i in range(5):
            self.audit.log(operation=f"op{i}", actor="user")
        # Tamper with an entry
        self.audit._entries[2].operation = "TAMPERED"
        valid, broken_at = self.audit.verify_chain()
        self.assertFalse(valid)
        self.assertIsNotNone(broken_at)

    def test_chain_hash_linkage(self):
        self.audit.log(operation="first", actor="a")
        self.audit.log(operation="second", actor="b")
        # Second entry's prev_hash should reference first entry
        self.assertEqual(
            self.audit._entries[1].prev_hash,
            self.audit._entries[0].entry_hash,
        )

    def test_first_entry_has_genesis_prev(self):
        self.audit.log(operation="first", actor="a")
        # First entry chains from a zero hash (genesis block)
        self.assertEqual(self.audit._entries[0].prev_hash, "0" * 64)

    def test_query_by_operation(self):
        self.audit.log(operation="read", path="a", actor="u")
        self.audit.log(operation="write", path="b", actor="u")
        self.audit.log(operation="read", path="c", actor="u")

        reads = self.audit.query(operation="read")
        self.assertEqual(len(reads), 2)
        for entry in reads:
            self.assertEqual(entry.operation, "read")

    def test_query_by_path(self):
        self.audit.log(operation="read", path="secret/db", actor="u")
        self.audit.log(operation="write", path="secret/api", actor="u")

        results = self.audit.query(path="secret/db")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].path, "secret/db")

    def test_query_by_actor(self):
        self.audit.log(operation="read", actor="alice")
        self.audit.log(operation="write", actor="bob")

        results = self.audit.query(actor="alice")
        self.assertEqual(len(results), 1)

    def test_query_limit(self):
        for i in range(20):
            self.audit.log(operation=f"op{i}", actor="u")
        results = self.audit.query(limit=5)
        self.assertEqual(len(results), 5)

    def test_query_combined_filters(self):
        self.audit.log(operation="read", path="secret/db", actor="alice")
        self.audit.log(operation="write", path="secret/db", actor="bob")
        self.audit.log(operation="read", path="secret/api", actor="alice")

        results = self.audit.query(operation="read", actor="alice")
        self.assertEqual(len(results), 2)

    def test_empty_log_chain_valid(self):
        valid, broken_at = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(broken_at)

    def test_single_entry_chain_valid(self):
        self.audit.log(operation="op", actor="u")
        valid, broken_at = self.audit.verify_chain()
        self.assertTrue(valid)

    def test_entry_to_dict(self):
        self.audit.log(
            operation="read",
            path="secret/x",
            actor="u1",
            outcome="allow",
            metadata={"version": 1},
        )
        d = self.audit._entries[0].to_dict()
        self.assertEqual(d["operation"], "read")
        self.assertEqual(d["path"], "secret/x")
        self.assertEqual(d["actor"], "u1")
        self.assertEqual(d["outcome"], "allow")
        self.assertIn("version", d["metadata"])

    def test_large_audit_log(self):
        for i in range(500):
            self.audit.log(operation=f"op{i}", actor="user")
        valid, _ = self.audit.verify_chain()
        self.assertTrue(valid)
        self.assertEqual(self.audit.entry_count, 500)


if __name__ == "__main__":
    unittest.main()
