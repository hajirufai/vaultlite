"""Tests for the main Vault class."""

import unittest

from vaultlite.vault import Vault
from vaultlite.types import Policy, Rule
from vaultlite.errors import (
    SealedError,
    AuthenticationError,
    AuthorizationError,
    SecretNotFoundError,
)


class TestVaultLifecycle(unittest.TestCase):

    def test_initialize(self):
        vault = Vault()
        result = vault.initialize(shares=5, threshold=3)
        self.assertTrue(result.root_token)
        self.assertEqual(len(result.unseal_keys), 5)

    def test_double_init_fails(self):
        vault = Vault()
        vault.initialize()
        with self.assertRaises(Exception):
            vault.initialize()

    def test_unseal(self):
        vault = Vault()
        result = vault.initialize(shares=5, threshold=5)
        for share in result.unseal_keys:
            vault.unseal(share)
        self.assertFalse(vault.seal_status.sealed)

    def test_seal(self):
        vault = Vault()
        result = vault.initialize(shares=5, threshold=5)
        for share in result.unseal_keys:
            vault.unseal(share)
        vault.seal()
        self.assertTrue(vault.seal_status.sealed)

    def test_health(self):
        vault = Vault()
        h = vault.health()
        self.assertFalse(h["initialized"])
        self.assertTrue(h["sealed"])
        vault.initialize()
        h = vault.health()
        self.assertTrue(h["initialized"])


def _setup_vault():
    """Helper: create and unseal a vault, returning vault + root token."""
    vault = Vault()
    result = vault.initialize(shares=3, threshold=3)
    for share in result.unseal_keys:
        vault.unseal(share)
    return vault, result.root_token


class TestVaultSecrets(unittest.TestCase):

    def test_write_and_read(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"password": "hunter2"}, token)
        result = vault.read("secret/db", token)
        self.assertEqual(result["data"]["password"], "hunter2")

    def test_read_nonexistent(self):
        vault, token = _setup_vault()
        with self.assertRaises(SecretNotFoundError):
            vault.read("secret/nope", token)

    def test_write_creates_version(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        r = vault.write("secret/db", {"v": 2}, token)
        self.assertEqual(r["version"], 2)

    def test_read_specific_version(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        vault.write("secret/db", {"v": 2}, token)
        r = vault.read("secret/db", token, version=1)
        self.assertEqual(r["data"]["v"], 1)

    def test_read_while_sealed(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        vault.seal()
        with self.assertRaises(SealedError):
            vault.read("secret/db", token)

    def test_write_with_bad_token(self):
        vault, token = _setup_vault()
        with self.assertRaises(AuthenticationError):
            vault.write("secret/db", {"v": 1}, "fake-token")

    def test_delete_and_undelete(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        vault.delete("secret/db", token)
        with self.assertRaises(SecretNotFoundError):
            vault.read("secret/db", token)
        vault.undelete("secret/db", token, 1)
        r = vault.read("secret/db", token)
        self.assertEqual(r["data"]["v"], 1)

    def test_destroy(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        vault.destroy("secret/db", token, 1)
        with self.assertRaises(SecretNotFoundError):
            vault.read("secret/db", token, version=1)

    def test_metadata(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        vault.write("secret/db", {"v": 2}, token)
        meta = vault.metadata("secret/db", token)
        self.assertEqual(meta["current_version"], 2)
        self.assertEqual(len(meta["versions"]), 2)

    def test_list_secrets(self):
        vault, token = _setup_vault()
        vault.write("secret/db/prod", {"v": 1}, token)
        vault.write("secret/db/staging", {"v": 1}, token)
        vault.write("secret/api/key", {"v": 1}, token)
        results = vault.list_secrets("secret/db", token)
        self.assertEqual(len(results), 2)

    def test_read_returns_lease(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        r = vault.read("secret/db", token)
        self.assertIn("lease_id", r)
        self.assertIn("lease_duration", r)


class TestVaultPolicies(unittest.TestCase):

    def test_create_and_get_policy(self):
        vault, token = _setup_vault()
        policy = Policy(
            name="test",
            rules=[Rule(path="secret/*", capabilities=["read"])],
        )
        vault.put_policy("test", policy, token)
        got = vault.get_policy("test", token)
        self.assertEqual(got.name, "test")

    def test_delete_policy(self):
        vault, token = _setup_vault()
        policy = Policy(
            name="test",
            rules=[Rule(path="*", capabilities=["read"])],
        )
        vault.put_policy("test", policy, token)
        vault.delete_policy("test", token)
        got = vault.get_policy("test", token)
        self.assertIsNone(got)

    def test_list_policies(self):
        vault, token = _setup_vault()
        policies = vault.list_policies(token)
        self.assertIn("default", policies)
        self.assertIn("root", policies)

    def test_policy_enforcement(self):
        vault, token = _setup_vault()
        # Create a read-only policy
        policy = Policy(
            name="readonly",
            rules=[Rule(path="secret/*", capabilities=["read", "list"])],
        )
        vault.put_policy("readonly", policy, token)

        # Create a token with that policy
        child = vault.create_token(token, policies=["readonly"])

        # Write with root token
        vault.write("secret/db", {"v": 1}, token)

        # Read with child should work
        r = vault.read("secret/db", child.token_id)
        self.assertEqual(r["data"]["v"], 1)

        # Write with child should fail
        with self.assertRaises(AuthorizationError):
            vault.write("secret/db", {"v": 2}, child.token_id)


class TestVaultTokens(unittest.TestCase):

    def test_create_child_token(self):
        vault, token = _setup_vault()
        child = vault.create_token(token, policies=["default"])
        self.assertFalse(child.is_root)

    def test_revoke_child_token(self):
        vault, token = _setup_vault()
        child = vault.create_token(token, policies=["default"])
        count = vault.revoke_token(token, child.token_id)
        self.assertEqual(count, 1)

    def test_lookup_token(self):
        vault, token = _setup_vault()
        info = vault.lookup_token(token)
        self.assertTrue(info["is_root"])


class TestVaultLeases(unittest.TestCase):

    def test_renew_lease(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        r = vault.read("secret/db", token)
        lease = vault.renew_lease(token, r["lease_id"])
        self.assertIsNotNone(lease.expires_at)

    def test_revoke_lease(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        r = vault.read("secret/db", token)
        result = vault.revoke_lease(token, r["lease_id"])
        self.assertTrue(result)


class TestVaultAudit(unittest.TestCase):

    def test_audit_log_populated(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        vault.read("secret/db", token)
        entries = vault.audit_log(token)
        # Should have: init, unseal(x3), write, read
        self.assertGreater(len(entries), 0)

    def test_verify_audit_chain(self):
        vault, token = _setup_vault()
        vault.write("secret/db", {"v": 1}, token)
        result = vault.verify_audit_chain(token)
        self.assertTrue(result["valid"])


class TestVaultAppRole(unittest.TestCase):

    def test_create_and_login(self):
        vault, token = _setup_vault()
        # Create a policy for the app
        policy = Policy(
            name="app",
            rules=[Rule(path="secret/*", capabilities=["read"])],
        )
        vault.put_policy("app", policy, token)

        # Create app-role
        result = vault.create_approle(token, "web-app", ["app"])

        # Login
        login_result = vault.approle_login(
            result["role_id"],
            result["secret_id"],
        )
        self.assertIn("token", login_result)
        self.assertIn("app", login_result["policies"])


if __name__ == "__main__":
    unittest.main()
