"""HTTP API server for VaultLite.

RESTful API using Python's stdlib http.server. No Flask, no FastAPI,
no external dependencies.

All endpoints except /v1/sys/health and /v1/sys/seal-status require
an X-Vault-Token header for authentication.

Routes:
    POST   /v1/sys/init              Initialize vault
    POST   /v1/sys/seal              Seal vault
    POST   /v1/sys/unseal            Provide unseal share
    GET    /v1/sys/seal-status       Check seal status
    GET    /v1/sys/health            Health check

    POST   /v1/secret/data/{path}    Write secret
    GET    /v1/secret/data/{path}    Read secret
    DELETE /v1/secret/data/{path}    Delete secret
    GET    /v1/secret/metadata/{path} Secret metadata

    POST   /v1/auth/token/create     Create token
    POST   /v1/auth/token/revoke     Revoke token
    GET    /v1/auth/token/lookup     Lookup token

    PUT    /v1/sys/policy/{name}     Create/update policy
    GET    /v1/sys/policy/{name}     Read policy
    DELETE /v1/sys/policy/{name}     Delete policy
    GET    /v1/sys/policy            List policies

    GET    /v1/sys/audit             Read audit log
"""

from __future__ import annotations

import json
import re
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Optional

from vaultlite.errors import (
    VaultLiteError,
    SealedError,
    AuthenticationError,
    AuthorizationError,
    SecretNotFoundError,
    VersionNotFoundError,
)
from vaultlite.types import Policy, Rule
from vaultlite.vault import Vault


class VaultHandler(BaseHTTPRequestHandler):
    """HTTP request handler for vault API endpoints."""

    # Reference to the shared Vault instance (set by VaultServer)
    vault: Vault

    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        """Send a JSON response."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, message: str, status: int = 400) -> None:
        """Send a JSON error response."""
        self._send_json({"error": message}, status)

    def _read_body(self) -> dict:
        """Read and parse the JSON request body."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        body = self.rfile.read(length)
        return json.loads(body.decode("utf-8"))

    def _get_token(self) -> Optional[str]:
        """Extract the authentication token from headers."""
        return self.headers.get("X-Vault-Token")

    def _require_token(self) -> str:
        """Extract token or send 401."""
        token = self._get_token()
        if not token:
            raise AuthenticationError("Missing X-Vault-Token header")
        return token

    def _route(self, method: str) -> None:
        """Route the request to the appropriate handler."""
        path = self.path.split("?")[0]  # Strip query string

        try:
            # System endpoints
            if path == "/v1/sys/health" and method == "GET":
                return self._handle_health()
            if path == "/v1/sys/seal-status" and method == "GET":
                return self._handle_seal_status()
            if path == "/v1/sys/init" and method == "POST":
                return self._handle_init()
            if path == "/v1/sys/seal" and method == "POST":
                return self._handle_seal()
            if path == "/v1/sys/unseal" and method == "POST":
                return self._handle_unseal()

            # Policy endpoints
            if path == "/v1/sys/policy" and method == "GET":
                return self._handle_list_policies()

            m = re.match(r"^/v1/sys/policy/(.+)$", path)
            if m:
                name = m.group(1)
                if method == "PUT":
                    return self._handle_put_policy(name)
                if method == "GET":
                    return self._handle_get_policy(name)
                if method == "DELETE":
                    return self._handle_delete_policy(name)

            # Audit endpoint
            if path == "/v1/sys/audit" and method == "GET":
                return self._handle_audit()

            # Secret endpoints
            m = re.match(r"^/v1/secret/data/(.+)$", path)
            if m:
                secret_path = m.group(1)
                if method == "POST":
                    return self._handle_write_secret(secret_path)
                if method == "GET":
                    return self._handle_read_secret(secret_path)
                if method == "DELETE":
                    return self._handle_delete_secret(secret_path)

            m = re.match(r"^/v1/secret/metadata/(.+)$", path)
            if m:
                secret_path = m.group(1)
                if method == "GET":
                    return self._handle_metadata(secret_path)

            m = re.match(r"^/v1/secret/undelete/(.+)$", path)
            if m and method == "POST":
                return self._handle_undelete(m.group(1))

            m = re.match(r"^/v1/secret/destroy/(.+)$", path)
            if m and method == "POST":
                return self._handle_destroy(m.group(1))

            # Auth endpoints
            if path == "/v1/auth/token/create" and method == "POST":
                return self._handle_create_token()
            if path == "/v1/auth/token/revoke" and method == "POST":
                return self._handle_revoke_token()
            if path == "/v1/auth/token/lookup" and method == "GET":
                return self._handle_lookup_token()
            if path == "/v1/auth/approle/login" and method == "POST":
                return self._handle_approle_login()

            self._send_error("Not found", 404)

        except AuthenticationError as e:
            self._send_error(str(e), 401)
        except AuthorizationError as e:
            self._send_error(str(e), 403)
        except SealedError as e:
            self._send_error(str(e), 503)
        except (SecretNotFoundError, VersionNotFoundError) as e:
            self._send_error(str(e), 404)
        except VaultLiteError as e:
            self._send_error(str(e), 400)
        except json.JSONDecodeError:
            self._send_error("Invalid JSON", 400)
        except Exception as e:
            self._send_error(f"Internal error: {type(e).__name__}", 500)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    # --- Handler methods ---

    def _handle_health(self):
        self._send_json(self.vault.health())

    def _handle_seal_status(self):
        self._send_json(self.vault.seal_status.to_dict())

    def _handle_init(self):
        body = self._read_body()
        result = self.vault.initialize(
            shares=body.get("shares", 5),
            threshold=body.get("threshold", 3),
        )
        self._send_json({
            "root_token": result.root_token,
            "unseal_keys": result.unseal_keys,
            "threshold": result.threshold,
            "total_shares": result.total_shares,
        })

    def _handle_seal(self):
        token = self._require_token()
        self.vault._authenticate(token)
        status = self.vault.seal()
        self._send_json(status.to_dict())

    def _handle_unseal(self):
        body = self._read_body()
        share = body.get("key", "")
        status = self.vault.unseal(share)
        self._send_json(status.to_dict())

    def _handle_write_secret(self, path: str):
        token = self._require_token()
        body = self._read_body()
        data = body.get("data", body)
        result = self.vault.write(path, data, token)
        self._send_json(result)

    def _handle_read_secret(self, path: str):
        token = self._require_token()
        version = None
        if "?" in self.path:
            qs = self.path.split("?")[1]
            for param in qs.split("&"):
                if param.startswith("version="):
                    version = int(param.split("=")[1])
        result = self.vault.read(path, token, version=version)
        self._send_json(result)

    def _handle_delete_secret(self, path: str):
        token = self._require_token()
        result = self.vault.delete(path, token)
        self._send_json(result)

    def _handle_metadata(self, path: str):
        token = self._require_token()
        result = self.vault.metadata(path, token)
        self._send_json(result)

    def _handle_undelete(self, path: str):
        token = self._require_token()
        body = self._read_body()
        version = body.get("version", 1)
        result = self.vault.undelete(path, token, version)
        self._send_json(result)

    def _handle_destroy(self, path: str):
        token = self._require_token()
        body = self._read_body()
        version = body.get("version", 1)
        result = self.vault.destroy(path, token, version)
        self._send_json(result)

    def _handle_create_token(self):
        token = self._require_token()
        body = self._read_body()
        child = self.vault.create_token(
            token=token,
            policies=body.get("policies"),
            ttl=body.get("ttl"),
            renewable=body.get("renewable", True),
            max_uses=body.get("max_uses", 0),
            metadata=body.get("metadata"),
        )
        self._send_json({
            "token": child.token_id,
            "policies": child.policies,
            "expires_at": child.expires_at,
        })

    def _handle_revoke_token(self):
        token = self._require_token()
        body = self._read_body()
        target = body.get("token", "")
        count = self.vault.revoke_token(token, target)
        self._send_json({"revoked_count": count})

    def _handle_lookup_token(self):
        token = self._require_token()
        result = self.vault.lookup_token(token)
        self._send_json(result)

    def _handle_approle_login(self):
        body = self._read_body()
        result = self.vault.approle_login(
            role_id=body.get("role_id", ""),
            secret_id=body.get("secret_id", ""),
        )
        self._send_json(result)

    def _handle_list_policies(self):
        token = self._require_token()
        policies = self.vault.list_policies(token)
        self._send_json({"policies": policies})

    def _handle_put_policy(self, name: str):
        token = self._require_token()
        body = self._read_body()
        rules = [Rule.from_dict(r) for r in body.get("rules", [])]
        policy = Policy(name=name, rules=rules)
        result = self.vault.put_policy(name, policy, token)
        self._send_json(result)

    def _handle_get_policy(self, name: str):
        token = self._require_token()
        policy = self.vault.get_policy(name, token)
        if policy is None:
            self._send_error(f"Policy not found: {name}", 404)
        else:
            self._send_json(policy.to_dict())

    def _handle_delete_policy(self, name: str):
        token = self._require_token()
        result = self.vault.delete_policy(name, token)
        self._send_json({"deleted": result})

    def _handle_audit(self):
        token = self._require_token()
        entries = self.vault.audit_log(token, limit=50)
        self._send_json({"entries": entries})


class VaultServer:
    """Vault HTTP server wrapper."""

    def __init__(self, vault: Vault, host: str = "127.0.0.1", port: int = 8200):
        self.vault = vault
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None

    def start(self, background: bool = False) -> None:
        """Start the HTTP server.

        Args:
            background: If True, run in a background thread.
        """
        handler = type("Handler", (VaultHandler,), {"vault": self.vault})
        self._server = HTTPServer((self.host, self.port), handler)

        if background:
            thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            thread.start()
        else:
            print(f"VaultLite server listening on {self.host}:{self.port}")
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        """Stop the HTTP server."""
        if self._server:
            self._server.shutdown()
