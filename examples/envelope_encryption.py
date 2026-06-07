"""Demonstrate AES envelope encryption internals.

Shows the low-level crypto that VaultLite uses under the hood:
1. PBKDF2 derives a master key from a password
2. Envelope encryption generates a unique DEK per secret
3. DEK is wrapped with the master key (KEK)
4. Data is encrypted with DEK, then HMAC-authenticated

This is the same flow that HashiCorp Vault uses.
"""

import os
from vaultlite.crypto.kdf import derive_key, generate_salt
from vaultlite.crypto.envelope import EnvelopeEncryption

# Step 1: Derive master key from password using PBKDF2
password = "my-vault-passphrase"
salt = generate_salt()
master_key = derive_key(password, salt, iterations=100_000, key_length=16)
print(f"Master key derived from password (PBKDF2, 100K iterations)")
print(f"  Salt: {salt[:8].hex()}...")
print(f"  Key:  {master_key.hex()}")

# Step 2: Create envelope encryption engine
envelope = EnvelopeEncryption(master_key)

# Step 3: Encrypt some secrets
secrets = {
    "database_password": b"s3cur3_p@ssw0rd!",
    "api_key": b"sk_live_abc123xyz789",
    "jwt_signing_key": os.urandom(32),
}

payloads = {}
print(f"\n--- Encrypting {len(secrets)} secrets ---\n")
for name, value in secrets.items():
    payload = envelope.encrypt(value)
    payloads[name] = payload
    print(f"  {name}:")
    print(f"    Ciphertext: {payload.ciphertext[:32]}...")
    print(f"    IV:         {payload.iv[:16]}...")
    print(f"    HMAC:       {payload.hmac[:32]}...")
    print(f"    Wrapped DEK:{payload.encrypted_dek[:32]}...")

# Step 4: Decrypt them back
print(f"\n--- Decrypting ---\n")
for name, payload in payloads.items():
    plaintext = envelope.decrypt(payload)
    display = plaintext.decode("utf-8", errors="replace")[:20]
    print(f"  {name}: {display}{'...' if len(plaintext) > 20 else ''}")

# Step 5: Show tamper detection
print(f"\n--- Tamper Detection ---\n")
import base64
tampered = payloads["api_key"]
ct = bytearray(base64.b64decode(tampered.ciphertext))
ct[0] ^= 0xFF  # Flip one bit
tampered.ciphertext = base64.b64encode(bytes(ct)).decode("ascii")
try:
    envelope.decrypt(tampered)
    print("  ⚠️  Tamper not detected!")
except Exception as e:
    print(f"  ✅ Tamper detected: {type(e).__name__}")

# Step 6: Master key rotation
print(f"\n--- Master Key Rotation ---\n")
new_key = os.urandom(16)
original_payloads = [envelope.encrypt(v) for v in secrets.values()]
rotated_payloads = envelope.rotate_master_key(new_key, original_payloads)

new_envelope = EnvelopeEncryption(new_key)
for (name, _), rotated in zip(secrets.items(), rotated_payloads):
    decrypted = new_envelope.decrypt(rotated)
    print(f"  {name}: decrypted successfully with new key")

print(f"\n✅ All {len(secrets)} secrets re-encrypted under new master key")
