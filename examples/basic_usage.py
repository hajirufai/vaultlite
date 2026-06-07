"""Basic VaultLite usage — write and read secrets."""

from vaultlite.vault import Vault

# 1. Create the vault
vault = Vault()

# 2. Initialize with 5 shares, threshold of 3
result = vault.initialize(shares=5, threshold=3)
print(f"Root token: {result.root_token[:20]}...")
print(f"Unseal keys: {len(result.unseal_keys)} shares, threshold={result.threshold}\n")

# 3. Unseal with 3 shares
for i in range(result.threshold):
    status = vault.unseal(result.unseal_keys[i])
    print(f"Share {i+1}: sealed={status.sealed}")

# 4. Write secrets
token = result.root_token

vault.write("secret/database/prod", {
    "host": "db.prod.internal",
    "port": "5432",
    "username": "app_user",
    "password": "s3cur3_p@ssw0rd!",
}, token)
print("\nWrote: secret/database/prod")

vault.write("secret/api/stripe", {
    "publishable_key": "pk_live_abc123",
    "secret_key": "sk_live_xyz789",
    "webhook_secret": "whsec_secret",
}, token)
print("Wrote: secret/api/stripe")

# 5. Read secrets back
db = vault.read("secret/database/prod", token)
print(f"\nRead: secret/database/prod (version {db['version']})")
print(f"  Host: {db['data']['host']}")
print(f"  User: {db['data']['username']}")
print(f"  Lease: {db['lease_id']}")

# 6. List secrets
secrets = vault.list_secrets("secret/database", token)
print(f"\nSecrets under 'secret/database': {secrets}")

# 7. Check health
print(f"\nHealth: {vault.health()}")
