"""Demonstrate hash-chained audit logging."""

from vaultlite.vault import Vault

# Setup
vault = Vault()
result = vault.initialize(shares=3, threshold=3)
for share in result.unseal_keys:
    vault.unseal(share)
token = result.root_token

# Perform some operations
vault.write("secret/database/prod", {"password": "db_pass"}, token)
vault.write("secret/api/stripe", {"key": "sk_live_123"}, token)
vault.read("secret/database/prod", token)
vault.read("secret/api/stripe", token)
vault.delete("secret/api/stripe", token)

# View audit trail
print("=== Audit Trail ===\n")
entries = vault.audit_log(token, limit=20)
for entry in entries:
    op = entry["operation"]
    path = entry["path"] or "-"
    outcome = entry["outcome"]
    actor = entry["actor"] or "system"
    print(f"  [{op:<18}] {path:<30} → {outcome:>5}  (by {actor})")

# Verify chain integrity
print("\n=== Chain Verification ===\n")
integrity = vault.verify_audit_chain(token)
print(f"  Chain valid: {'YES ✅' if integrity['valid'] else 'NO ❌'}")
print(f"  Total entries: {integrity['total_entries']}")
if integrity["broken_at"] is not None:
    print(f"  ⚠️  Chain broken at entry {integrity['broken_at']}")
