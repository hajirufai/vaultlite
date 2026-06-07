"""Command-line interface for VaultLite.

Usage:
    python -m vaultlite server               Start the API server
    python -m vaultlite init                  Initialize vault
    python -m vaultlite unseal <share>        Provide unseal share
    python -m vaultlite seal                  Seal vault
    python -m vaultlite status                Check seal status

    python -m vaultlite write <path> k=v ...  Write secret
    python -m vaultlite read <path>           Read secret
    python -m vaultlite delete <path>         Delete secret
    python -m vaultlite list <path>           List secrets

    python -m vaultlite policy write <name> <file>  Write policy
    python -m vaultlite token create                Create token
    python -m vaultlite audit                       View audit log
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from vaultlite.vault import Vault
from vaultlite.store import MemoryStore, FileStore, SQLiteStore
from vaultlite.api import VaultServer


def _get_vault(args) -> Vault:
    """Create a vault instance based on CLI args."""
    backend = getattr(args, "backend", "memory")
    store_path = getattr(args, "store_path", None)

    if backend == "file":
        store = FileStore(store_path or ".vaultlite/data")
    elif backend == "sqlite":
        store = SQLiteStore(store_path or ".vaultlite/vault.db")
    else:
        store = MemoryStore()

    return Vault(store=store)


def _format_output(data, format_type: str = "json") -> str:
    """Format output data."""
    if format_type == "json":
        return json.dumps(data, indent=2)
    # Table format for simple key-value
    if isinstance(data, dict):
        lines = []
        max_key = max(len(str(k)) for k in data.keys()) if data else 0
        for k, v in data.items():
            lines.append(f"  {k:<{max_key}}  {v}")
        return "\n".join(lines)
    return str(data)


def cmd_server(args):
    """Start the VaultLite API server."""
    vault = _get_vault(args)
    server = VaultServer(vault, host=args.host, port=args.port)
    server.start()


def cmd_init(args):
    """Initialize the vault."""
    vault = _get_vault(args)
    result = vault.initialize(
        shares=args.shares,
        threshold=args.threshold,
    )
    print("Vault initialized!")
    print(f"\nRoot Token: {result.root_token}")
    print(f"\nUnseal Keys (threshold {result.threshold}/{result.total_shares}):")
    for i, key in enumerate(result.unseal_keys, 1):
        print(f"  Key {i}: {key}")
    print(f"\nSave these keys securely. You need {result.threshold} to unseal.")


def cmd_status(args):
    """Check vault status."""
    vault = _get_vault(args)
    status = vault.health()
    print(_format_output(status))


def cmd_demo(args):
    """Run a quick interactive demo."""
    vault = Vault()

    print("=" * 50)
    print("  VaultLite — Interactive Demo")
    print("=" * 50)

    # Initialize
    num_shares = 3
    print(f"\n1. Initializing vault ({num_shares} unseal keys)...")
    result = vault.initialize(shares=num_shares, threshold=num_shares)
    print(f"   Root token: {result.root_token[:20]}...")
    print(f"   Generated {len(result.unseal_keys)} unseal keys")

    # Unseal
    print(f"\n2. Unsealing with {num_shares} shares...")
    for i in range(num_shares):
        status = vault.unseal(result.unseal_keys[i])
        print(f"   Share {i+1} accepted. Progress: {status.progress}/{status.threshold}")
    print(f"   Sealed: {status.sealed}")

    # Write secrets
    print("\n3. Writing secrets...")
    token = result.root_token
    vault.write("secret/database/prod", {
        "host": "db.example.com",
        "port": "5432",
        "username": "app_user",
        "password": "s3cur3_p@ss!",
    }, token)
    print("   Wrote: secret/database/prod")

    vault.write("secret/api/stripe", {
        "key": "sk_live_abc123",
        "webhook_secret": "whsec_xyz789",
    }, token)
    print("   Wrote: secret/api/stripe")

    # Read back
    print("\n4. Reading secrets...")
    db = vault.read("secret/database/prod", token)
    print(f"   secret/database/prod:")
    for k, v in db["data"].items():
        masked = v[:2] + "*" * (len(v) - 2) if len(v) > 2 else "**"
        print(f"     {k}: {masked}")
    print(f"   Version: {db['version']}, Lease: {db['lease_id']}")

    # Version a secret
    print("\n5. Updating secret (creates version 2)...")
    vault.write("secret/database/prod", {
        "host": "db.example.com",
        "port": "5432",
        "username": "app_user",
        "password": "n3w_p@ss_r0t@t3d!",
    }, token)
    print("   Updated: secret/database/prod (now version 2)")

    meta = vault.metadata("secret/database/prod", token)
    print(f"   Version history: {len(meta['versions'])} versions")

    # Audit log
    print("\n6. Checking audit trail...")
    entries = vault.audit_log(token, limit=5)
    for entry in entries[:5]:
        print(f"   [{entry['operation']:<15}] {entry['path']:<30} → {entry['outcome']}")

    # Verify chain
    integrity = vault.verify_audit_chain(token)
    print(f"   Chain integrity: {'VALID' if integrity['valid'] else 'BROKEN'}")
    print(f"   Total entries: {integrity['total_entries']}")

    # Seal
    print("\n7. Sealing vault...")
    vault.seal()
    print(f"   Sealed: {vault.seal_status.sealed}")

    # Try to read while sealed
    print("\n8. Attempting read while sealed...")
    try:
        vault.read("secret/database/prod", token)
    except Exception as e:
        print(f"   Blocked: {e}")

    print("\n" + "=" * 50)
    print("  Demo complete! All operations logged and verified.")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        prog="vaultlite",
        description="VaultLite — Lightweight Secrets Manager",
    )

    parser.add_argument(
        "--backend", choices=["memory", "file", "sqlite"],
        default="memory", help="Storage backend",
    )
    parser.add_argument("--store-path", help="Path for file/sqlite backend")

    sub = parser.add_subparsers(dest="command")

    # server
    srv = sub.add_parser("server", help="Start API server")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8200)

    # init
    init = sub.add_parser("init", help="Initialize vault")
    init.add_argument("--shares", type=int, default=5)
    init.add_argument("--threshold", type=int, default=3)

    # status
    sub.add_parser("status", help="Check vault status")

    # demo
    sub.add_parser("demo", help="Run interactive demo")

    args = parser.parse_args()

    commands = {
        "server": cmd_server,
        "init": cmd_init,
        "status": cmd_status,
        "demo": cmd_demo,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
