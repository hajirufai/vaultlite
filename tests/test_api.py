"""Tests for the HTTP API server."""

import json
import threading
import time
import unittest
import urllib.request
import urllib.error

from vaultlite.vault import Vault
from vaultlite.api import VaultServer


class TestVaultAPI(unittest.TestCase):
    """Integration tests for the REST API."""

    @classmethod
    def setUpClass(cls):
        cls.vault = Vault()
        cls.port = 18200
        cls.server = VaultServer(cls.vault, port=cls.port)
        cls.server.start(background=True)
        time.sleep(0.1)  # Wait for server to start
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def _request(self, method, path, data=None, token=None):
        url = f"{self.base}{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("X-Vault-Token", token)
        try:
            resp = urllib.request.urlopen(req)
            return json.loads(resp.read().decode()), resp.status
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode()), e.code

    def test_health(self):
        data, status = self._request("GET", "/v1/sys/health")
        self.assertEqual(status, 200)
        self.assertIn("sealed", data)

    def test_init_unseal_flow(self):
        # Initialize
        data, status = self._request("POST", "/v1/sys/init", {
            "shares": 3, "threshold": 3,
        })
        self.assertEqual(status, 200)
        root_token = data["root_token"]
        unseal_keys = data["unseal_keys"]

        # Check seal status
        data, status = self._request("GET", "/v1/sys/seal-status")
        self.assertEqual(status, 200)
        self.assertTrue(data["sealed"])

        # Unseal
        for key in unseal_keys:
            data, status = self._request("POST", "/v1/sys/unseal", {"key": key})
            self.assertEqual(status, 200)

        self.assertFalse(data["sealed"])

        # Write a secret
        data, status = self._request(
            "POST", "/v1/secret/data/test/api",
            {"data": {"key": "value"}},
            token=root_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["version"], 1)

        # Read it back
        data, status = self._request(
            "GET", "/v1/secret/data/test/api",
            token=root_token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["data"]["key"], "value")

    def test_401_without_token(self):
        data, status = self._request("GET", "/v1/secret/data/anything")
        self.assertEqual(status, 401)

    def test_404_route(self):
        data, status = self._request("GET", "/v1/nonexistent")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
