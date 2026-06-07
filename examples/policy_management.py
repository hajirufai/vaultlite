"""Demonstrate policy-based access control."""

from vaultlite.vault import Vault
from vaultlite.types import Policy, Rule

# Setup
vault = Vault()
result = vault.initialize(shares=3, threshold=3)
for share in result.unseal_keys:
    vault.unseal(share)
root = result.root_token

# Write a secret with root token
vault.write("secret/database/prod", {"password": "root-managed"}, root)

# Create a read-only policy for the database team
db_reader_policy = Policy(
    name="db-reader",
    rules=[
        Rule(path="secret/database/*", capabilities=["read", "list"]),
    ],
)
vault.put_policy("db-reader", db_reader_policy, root)

# Create a token with the db-reader policy
reader_token = vault.create_token(root, policies=["db-reader"])
print(f"Reader token: {reader_token.token_id[:20]}...")
print(f"Policies: {reader_token.policies}")

# Read works
result = vault.read("secret/database/prod", reader_token.token_id)
print(f"\n✅ Read succeeded: {result['data']}")

# Write fails (no write capability)
try:
    vault.write("secret/database/prod", {"password": "hacked"}, reader_token.token_id)
except Exception as e:
    print(f"❌ Write blocked: {e}")

# Create a full-access policy for database admins
db_admin_policy = Policy(
    name="db-admin",
    rules=[
        Rule(path="secret/database/*", capabilities=["read", "write", "delete", "list"]),
    ],
)
vault.put_policy("db-admin", db_admin_policy, root)

# Create an admin token
admin_token = vault.create_token(root, policies=["db-admin"])

# Admin can write
vault.write("secret/database/staging", {"password": "staging-pass"}, admin_token.token_id)
print(f"\n✅ Admin write succeeded")

# List all policies
policies = vault.list_policies(root)
print(f"\nAll policies: {policies}")
