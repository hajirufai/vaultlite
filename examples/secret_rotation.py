"""Demonstrate secret versioning and rotation."""

from vaultlite.vault import Vault

# Setup
vault = Vault()
result = vault.initialize(shares=3, threshold=3)
for share in result.unseal_keys:
    vault.unseal(share)
token = result.root_token

# Write initial secret (version 1)
vault.write("secret/database/prod", {
    "password": "initial_password_2024",
    "rotation_date": "2024-01-01",
}, token)
print("Version 1: initial_password_2024")

# Rotate password (version 2)
vault.write("secret/database/prod", {
    "password": "rotated_password_q2_2024",
    "rotation_date": "2024-04-01",
}, token)
print("Version 2: rotated_password_q2_2024")

# Rotate again (version 3)
vault.write("secret/database/prod", {
    "password": "rotated_password_q3_2024",
    "rotation_date": "2024-07-01",
}, token)
print("Version 3: rotated_password_q3_2024")

# Read current version
current = vault.read("secret/database/prod", token)
print(f"\nCurrent: v{current['version']} → {current['data']['password']}")

# Read a specific old version
old = vault.read("secret/database/prod", token, version=1)
print(f"Old:     v{old['version']} → {old['data']['password']}")

# View version history
meta = vault.metadata("secret/database/prod", token)
print(f"\nVersion history ({len(meta['versions'])} versions):")
for v in meta["versions"]:
    status = ""
    if v["deleted"]:
        status = " [DELETED]"
    if v["destroyed"]:
        status = " [DESTROYED]"
    print(f"  v{v['version']}: created by {v['created_by']}{status}")

# Soft-delete old version (can be recovered)
vault.delete("secret/database/prod", token, version=1)
print("\nSoft-deleted version 1")

# Undelete it
vault.undelete("secret/database/prod", token, 1)
print("Undeleted version 1")

# Permanently destroy old version (no recovery)
vault.destroy("secret/database/prod", token, 1)
print("Destroyed version 1 permanently")

# Try to read destroyed version
try:
    vault.read("secret/database/prod", token, version=1)
except Exception as e:
    print(f"❌ Cannot read: {e}")
