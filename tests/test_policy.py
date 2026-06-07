"""Tests for access control policies."""

import unittest

from vaultlite.policy import PolicyManager, validate_policy, _path_matches
from vaultlite.types import Policy, Rule
from vaultlite.errors import PolicyError


class TestPathMatching(unittest.TestCase):

    def test_exact_match(self):
        self.assertTrue(_path_matches("secret/data/db", "secret/data/db"))

    def test_exact_no_match(self):
        self.assertFalse(_path_matches("secret/data/db", "secret/data/api"))

    def test_glob_star(self):
        self.assertTrue(_path_matches("secret/data/*", "secret/data/db"))

    def test_glob_star_deep_match(self):
        # fnmatch treats * as matching / too — use path-level prefix if needed
        self.assertTrue(_path_matches("secret/data/*", "secret/data/db/pass"))

    def test_double_star(self):
        self.assertTrue(_path_matches("secret/**", "secret/data/db/pass"))
        self.assertTrue(_path_matches("secret/**", "secret/anything"))

    def test_root_star(self):
        self.assertTrue(_path_matches("*", "anything/at/all"))

    def test_empty_path(self):
        self.assertFalse(_path_matches("secret/*", ""))


class TestPolicyValidation(unittest.TestCase):

    def test_valid_policy(self):
        policy = Policy(
            name="test",
            rules=[Rule(path="secret/*", capabilities=["read"])],
        )
        validate_policy(policy)  # Should not raise

    def test_empty_name(self):
        with self.assertRaises(PolicyError):
            validate_policy(Policy(name="", rules=[Rule(path="*")]))

    def test_no_rules(self):
        with self.assertRaises(PolicyError):
            validate_policy(Policy(name="test", rules=[]))

    def test_invalid_capability(self):
        with self.assertRaises(PolicyError):
            validate_policy(Policy(
                name="test",
                rules=[Rule(path="*", capabilities=["fly"])],
            ))


class TestPolicyManager(unittest.TestCase):

    def setUp(self):
        self.pm = PolicyManager()

    def test_default_policies_exist(self):
        self.assertIn("default", self.pm.list_policies())
        self.assertIn("root", self.pm.list_policies())

    def test_add_custom_policy(self):
        policy = Policy(
            name="db-reader",
            rules=[Rule(path="secret/db/*", capabilities=["read", "list"])],
        )
        self.pm.add_policy(policy)
        self.assertIn("db-reader", self.pm.list_policies())

    def test_get_policy(self):
        self.assertIsNotNone(self.pm.get_policy("root"))
        self.assertIsNone(self.pm.get_policy("nonexistent"))

    def test_delete_custom_policy(self):
        policy = Policy(
            name="temp",
            rules=[Rule(path="*", capabilities=["read"])],
        )
        self.pm.add_policy(policy)
        self.assertTrue(self.pm.delete_policy("temp"))
        self.assertNotIn("temp", self.pm.list_policies())

    def test_cannot_delete_builtin(self):
        with self.assertRaises(PolicyError):
            self.pm.delete_policy("root")
        with self.assertRaises(PolicyError):
            self.pm.delete_policy("default")

    def test_check_access_root_allows_all(self):
        self.assertTrue(
            self.pm.check_access(["root"], "anything", "read")
        )
        self.assertTrue(
            self.pm.check_access(["root"], "anything", "sudo")
        )

    def test_check_access_default_read(self):
        self.assertTrue(
            self.pm.check_access(["default"], "secret/db", "read")
        )

    def test_check_access_default_no_write(self):
        self.assertFalse(
            self.pm.check_access(["default"], "secret/db", "write")
        )

    def test_check_access_no_policy(self):
        self.assertFalse(
            self.pm.check_access([], "secret/db", "read")
        )

    def test_check_access_invalid_capability(self):
        self.assertFalse(
            self.pm.check_access(["root"], "path", "fly")
        )

    def test_get_capabilities(self):
        caps = self.pm.get_capabilities(["root"], "anything")
        self.assertEqual(caps, {"read", "write", "delete", "list", "sudo"})

    def test_multiple_policies_merge(self):
        p1 = Policy(
            name="reader",
            rules=[Rule(path="secret/*", capabilities=["read"])],
        )
        p2 = Policy(
            name="writer",
            rules=[Rule(path="secret/*", capabilities=["write"])],
        )
        self.pm.add_policy(p1)
        self.pm.add_policy(p2)
        caps = self.pm.get_capabilities(["reader", "writer"], "secret/db")
        self.assertIn("read", caps)
        self.assertIn("write", caps)

    def test_serialization_round_trip(self):
        p = Policy(
            name="custom",
            rules=[Rule(path="test/*", capabilities=["read", "write"])],
        )
        self.pm.add_policy(p)
        data = self.pm.to_dict()
        new_pm = PolicyManager()
        new_pm.load_from_dict(data)
        self.assertIn("custom", new_pm.list_policies())


if __name__ == "__main__":
    unittest.main()
