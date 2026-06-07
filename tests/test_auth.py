"""Tests for authentication (tokens and app-roles)."""

import time
import unittest

from vaultlite.auth import TokenManager
from vaultlite.errors import AuthenticationError


class TestTokenCreation(unittest.TestCase):

    def setUp(self):
        self.tm = TokenManager()

    def test_create_root_token(self):
        token = self.tm.create_root_token()
        self.assertTrue(token.is_root)
        self.assertIn("root", token.policies)
        self.assertTrue(token.token_id.startswith("hvs."))

    def test_create_child_token(self):
        token = self.tm.create_token(
            policies=["default"],
            ttl=3600,
        )
        self.assertFalse(token.is_root)
        self.assertIn("default", token.policies)
        self.assertIsNotNone(token.expires_at)

    def test_create_token_no_ttl(self):
        token = self.tm.create_token(policies=["default"])
        self.assertIsNone(token.expires_at)

    def test_create_token_with_parent(self):
        parent = self.tm.create_root_token()
        child = self.tm.create_token(
            policies=["default"],
            parent_token=parent.token_id,
        )
        self.assertEqual(child.parent_token, parent.token_id)

    def test_create_token_with_max_uses(self):
        token = self.tm.create_token(
            policies=["default"],
            max_uses=3,
        )
        self.assertEqual(token.max_uses, 3)


class TestTokenValidation(unittest.TestCase):

    def setUp(self):
        self.tm = TokenManager()

    def test_validate_valid_token(self):
        token = self.tm.create_root_token()
        validated = self.tm.validate_token(token.token_id)
        self.assertEqual(validated.token_id, token.token_id)

    def test_validate_increments_use_count(self):
        token = self.tm.create_token(policies=["default"])
        self.assertEqual(token.use_count, 0)
        self.tm.validate_token(token.token_id)
        self.assertEqual(token.use_count, 1)

    def test_validate_invalid_token(self):
        with self.assertRaises(AuthenticationError):
            self.tm.validate_token("fake-token")

    def test_validate_expired_token(self):
        token = self.tm.create_token(
            policies=["default"],
            ttl=0.01,
        )
        time.sleep(0.02)
        with self.assertRaises(AuthenticationError):
            self.tm.validate_token(token.token_id)

    def test_validate_revoked_token(self):
        token = self.tm.create_token(policies=["default"])
        self.tm.revoke_token(token.token_id)
        with self.assertRaises(AuthenticationError):
            self.tm.validate_token(token.token_id)

    def test_validate_max_uses_exhausted(self):
        token = self.tm.create_token(policies=["default"], max_uses=2)
        self.tm.validate_token(token.token_id)
        self.tm.validate_token(token.token_id)
        with self.assertRaises(AuthenticationError):
            self.tm.validate_token(token.token_id)


class TestTokenRevocation(unittest.TestCase):

    def setUp(self):
        self.tm = TokenManager()

    def test_revoke_single(self):
        token = self.tm.create_token(policies=["default"])
        count = self.tm.revoke_token(token.token_id)
        self.assertEqual(count, 1)
        self.assertTrue(token.revoked)

    def test_revoke_with_children(self):
        parent = self.tm.create_root_token()
        child = self.tm.create_token(
            policies=["default"],
            parent_token=parent.token_id,
        )
        count = self.tm.revoke_token(parent.token_id)
        self.assertEqual(count, 2)
        self.assertTrue(parent.revoked)
        self.assertTrue(child.revoked)

    def test_revoke_nonexistent(self):
        count = self.tm.revoke_token("fake")
        self.assertEqual(count, 0)


class TestTokenRenewal(unittest.TestCase):

    def setUp(self):
        self.tm = TokenManager()

    def test_renew_extends_ttl(self):
        token = self.tm.create_token(policies=["default"], ttl=100)
        old_expires = token.expires_at
        self.tm.renew_token(token.token_id, 200)
        self.assertGreater(token.expires_at, old_expires)

    def test_renew_non_renewable(self):
        token = self.tm.create_token(
            policies=["default"],
            renewable=False,
        )
        with self.assertRaises(AuthenticationError):
            self.tm.renew_token(token.token_id, 100)


class TestAppRole(unittest.TestCase):

    def setUp(self):
        self.tm = TokenManager()

    def test_create_approle(self):
        result = self.tm.create_approle(
            role_name="web-app",
            policies=["default"],
        )
        self.assertIn("role_id", result)
        self.assertIn("secret_id", result)

    def test_approle_login(self):
        result = self.tm.create_approle(
            role_name="web-app",
            policies=["default"],
            token_ttl=1800,
        )
        token = self.tm.approle_login(result["role_id"], result["secret_id"])
        self.assertIn("default", token.policies)
        self.assertIsNotNone(token.expires_at)

    def test_approle_wrong_secret(self):
        result = self.tm.create_approle(
            role_name="test",
            policies=["default"],
        )
        with self.assertRaises(AuthenticationError):
            self.tm.approle_login(result["role_id"], "wrong-secret")

    def test_approle_wrong_role(self):
        with self.assertRaises(AuthenticationError):
            self.tm.approle_login("fake-role", "fake-secret")


class TestTokenSerialization(unittest.TestCase):

    def setUp(self):
        self.tm = TokenManager()

    def test_round_trip(self):
        self.tm.create_root_token()
        self.tm.create_token(policies=["default"], ttl=3600)
        self.tm.create_approle("app", ["default"])

        data = self.tm.to_dict()
        new_tm = TokenManager()
        new_tm.load_from_dict(data)

        self.assertEqual(
            len(new_tm._tokens),
            len(self.tm._tokens),
        )


if __name__ == "__main__":
    unittest.main()
