"""Tests for seal/unseal mechanism."""

import unittest

from vaultlite.seal import SealManager, split_key, reconstruct_key
from vaultlite.errors import InitializationError, SealedError


class TestKeySplitting(unittest.TestCase):

    def test_split_and_reconstruct(self):
        key = b"0123456789abcdef"
        shares = split_key(key, 5, 3)
        self.assertEqual(len(shares), 5)
        # XOR all shares should give back the key
        reconstructed = reconstruct_key(shares)
        self.assertEqual(reconstructed, key)

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            split_key(b"key", 3, 5)  # threshold > shares
        with self.assertRaises(ValueError):
            split_key(b"key", 3, 0)  # threshold < 1

    def test_single_share(self):
        key = b"0123456789abcdef"
        shares = split_key(key, 1, 1)
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0], key)

    def test_shares_are_different(self):
        key = b"0123456789abcdef"
        shares = split_key(key, 5, 3)
        # All shares should be different (statistically)
        unique = set(s.hex() for s in shares)
        self.assertGreater(len(unique), 1)


class TestSealManager(unittest.TestCase):

    def setUp(self):
        self.seal = SealManager()

    def test_initial_state(self):
        status = self.seal.status
        self.assertFalse(status.initialized)
        self.assertTrue(status.sealed)

    def test_initialize(self):
        result = self.seal.initialize(5, 3)
        self.assertEqual(len(result.unseal_keys), 5)
        self.assertEqual(result.threshold, 3)
        self.assertTrue(result.root_token.startswith("hvs.root-"))
        self.assertTrue(self.seal.status.initialized)
        self.assertTrue(self.seal.status.sealed)

    def test_double_init_fails(self):
        self.seal.initialize(5, 3)
        with self.assertRaises(InitializationError):
            self.seal.initialize(5, 3)

    def test_unseal_with_threshold_shares(self):
        result = self.seal.initialize(5, 5)
        # Provide all shares
        for i, share in enumerate(result.unseal_keys):
            status = self.seal.provide_unseal_share(share)
            if i < 4:
                self.assertTrue(status.sealed)
            else:
                self.assertFalse(status.sealed)

    def test_master_key_available_when_unsealed(self):
        result = self.seal.initialize(5, 5)
        for share in result.unseal_keys:
            self.seal.provide_unseal_share(share)
        self.assertIsNotNone(self.seal.master_key)
        self.assertEqual(len(self.seal.master_key), 16)

    def test_master_key_none_when_sealed(self):
        self.assertIsNone(self.seal.master_key)

    def test_seal_forgets_key(self):
        result = self.seal.initialize(5, 5)
        for share in result.unseal_keys:
            self.seal.provide_unseal_share(share)
        self.seal.seal()
        self.assertTrue(self.seal.status.sealed)
        self.assertIsNone(self.seal.master_key)

    def test_require_unsealed_when_sealed(self):
        self.seal.initialize(5, 3)
        with self.assertRaises(SealedError):
            self.seal.require_unsealed()

    def test_require_unsealed_when_not_initialized(self):
        with self.assertRaises(InitializationError):
            self.seal.require_unsealed()

    def test_require_unsealed_success(self):
        result = self.seal.initialize(5, 5)
        for share in result.unseal_keys:
            self.seal.provide_unseal_share(share)
        key = self.seal.require_unsealed()
        self.assertEqual(len(key), 16)

    def test_unseal_progress(self):
        result = self.seal.initialize(5, 3)
        status = self.seal.provide_unseal_share(result.unseal_keys[0])
        self.assertEqual(status.progress, 1)
        status = self.seal.provide_unseal_share(result.unseal_keys[1])
        self.assertEqual(status.progress, 2)

    def test_unseal_before_init(self):
        with self.assertRaises(InitializationError):
            self.seal.provide_unseal_share("fake-share")

    def test_serialization(self):
        self.seal.initialize(5, 3)
        data = self.seal.to_dict()
        new_seal = SealManager()
        new_seal.load_from_dict(data)
        self.assertTrue(new_seal.status.initialized)
        self.assertTrue(new_seal.status.sealed)
        self.assertEqual(new_seal._threshold, 3)


if __name__ == "__main__":
    unittest.main()
