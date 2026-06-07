"""Tests for lease management."""

import time
import unittest

from vaultlite.lease import LeaseManager
from vaultlite.errors import LeaseError


class TestLeaseCreation(unittest.TestCase):

    def setUp(self):
        self.lm = LeaseManager(default_ttl=60, max_ttl=300)

    def test_create_lease(self):
        lease = self.lm.create_lease("secret/db", "tok1")
        self.assertTrue(lease.lease_id.startswith("lease."))
        self.assertEqual(lease.secret_path, "secret/db")
        self.assertEqual(lease.token_id, "tok1")
        self.assertEqual(lease.ttl, 60)

    def test_create_with_custom_ttl(self):
        lease = self.lm.create_lease("secret/db", "tok1", ttl=120)
        self.assertEqual(lease.ttl, 120)

    def test_ttl_capped_at_max(self):
        lease = self.lm.create_lease("secret/db", "tok1", ttl=99999)
        self.assertEqual(lease.ttl, 300)  # max_ttl

    def test_non_renewable(self):
        lease = self.lm.create_lease("secret/db", "tok1", renewable=False)
        self.assertFalse(lease.renewable)


class TestLeaseRenewal(unittest.TestCase):

    def setUp(self):
        self.lm = LeaseManager(default_ttl=60, max_ttl=300)

    def test_renew(self):
        lease = self.lm.create_lease("secret/db", "tok1")
        old_expires = lease.expires_at
        time.sleep(0.01)
        renewed = self.lm.renew_lease(lease.lease_id)
        self.assertGreater(renewed.expires_at, old_expires)

    def test_renew_with_ttl(self):
        lease = self.lm.create_lease("secret/db", "tok1")
        renewed = self.lm.renew_lease(lease.lease_id, ttl=120)
        self.assertEqual(renewed.ttl, 120)

    def test_renew_nonexistent(self):
        with self.assertRaises(LeaseError):
            self.lm.renew_lease("fake-lease")

    def test_renew_non_renewable(self):
        lease = self.lm.create_lease("secret/db", "tok1", renewable=False)
        with self.assertRaises(LeaseError):
            self.lm.renew_lease(lease.lease_id)


class TestLeaseRevocation(unittest.TestCase):

    def setUp(self):
        self.lm = LeaseManager()

    def test_revoke_lease(self):
        lease = self.lm.create_lease("secret/db", "tok1")
        self.assertTrue(self.lm.revoke_lease(lease.lease_id))
        self.assertTrue(lease.revoked)

    def test_revoke_nonexistent(self):
        self.assertFalse(self.lm.revoke_lease("fake"))

    def test_revoke_by_path(self):
        self.lm.create_lease("secret/db", "tok1")
        self.lm.create_lease("secret/db", "tok2")
        self.lm.create_lease("secret/api", "tok1")
        count = self.lm.revoke_by_path("secret/db")
        self.assertEqual(count, 2)

    def test_revoke_by_token(self):
        self.lm.create_lease("secret/a", "tok1")
        self.lm.create_lease("secret/b", "tok1")
        self.lm.create_lease("secret/c", "tok2")
        count = self.lm.revoke_by_token("tok1")
        self.assertEqual(count, 2)


class TestLeaseLookup(unittest.TestCase):

    def setUp(self):
        self.lm = LeaseManager()

    def test_lookup(self):
        lease = self.lm.create_lease("secret/db", "tok1")
        found = self.lm.lookup_lease(lease.lease_id)
        self.assertEqual(found.lease_id, lease.lease_id)

    def test_lookup_missing(self):
        self.assertIsNone(self.lm.lookup_lease("fake"))

    def test_list_active(self):
        self.lm.create_lease("secret/a", "tok1")
        self.lm.create_lease("secret/b", "tok1")
        active = self.lm.list_leases("secret/")
        self.assertEqual(len(active), 2)

    def test_list_excludes_revoked(self):
        l1 = self.lm.create_lease("secret/a", "tok1")
        self.lm.create_lease("secret/b", "tok1")
        self.lm.revoke_lease(l1.lease_id)
        active = self.lm.list_leases("secret/")
        self.assertEqual(len(active), 1)

    def test_cleanup_expired(self):
        # Create a short-lived lease
        self.lm.create_lease("secret/a", "tok1", ttl=0.01)
        self.lm.create_lease("secret/b", "tok1", ttl=3600)
        time.sleep(0.02)
        cleaned = self.lm.cleanup_expired()
        self.assertEqual(cleaned, 1)


if __name__ == "__main__":
    unittest.main()
