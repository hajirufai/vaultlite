# VaultLite

A lightweight secrets manager built from scratch in Python. Zero external dependencies — even the AES-128 encryption is implemented byte-by-byte from the NIST FIPS 197 specification.

## What is this?

VaultLite is a simplified version of [HashiCorp Vault](https://www.vaultproject.io/), implementing the core concepts of enterprise secrets management:

- **AES-128 block cipher** — S-box substitution, ShiftRows, MixColumns, key expansion. All 10 rounds, no shortcuts.
- **Envelope encryption** — each secret gets a unique Data Encryption Key (DEK), wrapped by a master Key Encryption Key (KEK).
- **Seal/unseal mechanism** — master key split into shares using XOR-based secret splitting. All shares required to reconstruct.
- **Token-based authentication** — root tokens, child tokens, TTL, max uses, token trees with cascading revocation.
- **Path-based access control** — glob-matching policies with capability-based permissions (read/write/delete/list/sudo).
- **Hash-chained audit log** — every operation logged with SHA-256 chain linking. Tamper with any entry and the chain breaks.
- **Secret versioning** — version history, soft-delete/undelete, permanent destruction.
- **TTL-based leasing** — every secret read gets a lease that expires. Renewal and revocation supported.
- **App-role authentication** — machine-to-machine auth with role IDs and secret IDs.
- **RESTful HTTP API** — ~25 endpoints using only Python's `http.server`.
- **Three storage backends** — in-memory, file-based, and SQLite.

Everything runs on the Python standard library. No `cryptography`, no `pycryptodome`, no `flask`.

## Quick Start

```bash
git clone https://github.com/hajirufai/vaultlite.git
cd vaultlite

# Run the interactive demo
python -m vaultlite demo

# Or use it as a library
python examples/basic_usage.py
```

## Usage

### As a Library

```python
from vaultlite.vault import Vault

# Create and initialize
vault = Vault()
result = vault.initialize(shares=3, threshold=3)

# Unseal
for share in result.unseal_keys:
    vault.unseal(share)

# Write a secret
vault.write("secret/database/prod", {
    "host": "db.internal",
    "password": "s3cur3_p@ss!",
}, result.root_token)

# Read it back
secret = vault.read("secret/database/prod", result.root_token)
print(secret["data"]["password"])  # s3cur3_p@ss!
```

### As an HTTP Server

```bash
python -m vaultlite server --port 8200
```

```bash
# Initialize
curl -X POST http://localhost:8200/v1/sys/init \
  -d '{"shares": 3, "threshold": 3}'

# Unseal (repeat with each key)
curl -X POST http://localhost:8200/v1/sys/unseal \
  -d '{"key": "..."}'

# Write a secret
curl -X POST http://localhost:8200/v1/secret/data/myapp \
  -H "X-Vault-Token: hvs.root-..." \
  -d '{"data": {"api_key": "sk_live_123"}}'

# Read it back
curl http://localhost:8200/v1/secret/data/myapp \
  -H "X-Vault-Token: hvs.root-..."
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     HTTP API (api.py)                     │
│              25+ RESTful endpoints, stdlib only           │
├──────────────────────────────────────────────────────────┤
│                     Vault (vault.py)                      │
│          Central orchestrator — coordinates all           │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│   Auth   │  Policy  │  Audit   │  Lease   │  Versioning  │
│ Tokens   │ ACL      │ Hash     │ TTL      │ History      │
│ AppRole  │ Glob     │ Chain    │ Renewal  │ Soft-delete  │
│ Tree     │ Caps     │ Tamper   │ Cleanup  │ Destroy      │
├──────────┴──────────┴──────────┴──────────┴──────────────┤
│                 Seal Manager (seal.py)                    │
│          XOR key splitting, unseal ceremony               │
├──────────────────────────────────────────────────────────┤
│               Envelope Encryption (crypto/)               │
│    AES-128 → CBC Mode → PKCS7 → HMAC → Key Wrapping     │
├──────────────────────────────────────────────────────────┤
│                   Storage Backends                        │
│         MemoryStore │ FileStore │ SQLiteStore             │
└──────────────────────────────────────────────────────────┘
```

## The AES Implementation

The heart of VaultLite is a from-scratch AES-128 implementation (`vaultlite/crypto/aes.py`). Every transformation is coded explicitly:

1. **S-Box** — Full 256-entry substitution table from GF(2⁸) inversion
2. **SubBytes** — Apply S-Box to every byte in the 4×4 state matrix
3. **ShiftRows** — Circular left-shift rows by 0, 1, 2, 3 positions
4. **MixColumns** — Matrix multiplication in GF(2⁸) using xtime
5. **AddRoundKey** — XOR state with the round key
6. **Key Expansion** — Transform 16-byte key into 11 round keys (44 words)

Validated against the NIST FIPS 197 Appendix B test vector:

```
Key:       2b7e1516 28aed2a6 abf71588 09cf4f3c
Plaintext: 3243f6a8 885a308d 313198a2 e0370734
Expected:  3925841d 02dc09fb dc118597 196a0b32  ✓
```

## Project Structure

```
vaultlite/
├── crypto/
│   ├── aes.py          # AES-128 block cipher from scratch
│   ├── modes.py        # CBC mode of operation
│   ├── padding.py      # PKCS7 padding
│   ├── kdf.py          # PBKDF2-HMAC-SHA256 key derivation
│   ├── mac.py          # HMAC-SHA256 authentication
│   └── envelope.py     # Envelope encryption (DEK + KEK)
├── vault.py            # Central vault orchestrator
├── seal.py             # XOR key splitting + unseal
├── auth.py             # Token management + app-role auth
├── policy.py           # Path-based access control
├── audit.py            # Hash-chained audit logging
├── lease.py            # TTL-based secret leasing
├── versioning.py       # Secret version history
├── store.py            # Storage backends (memory/file/sqlite)
├── api.py              # HTTP API server
├── cli.py              # Command-line interface
├── types.py            # Data types
├── errors.py           # Custom exceptions
└── utils.py            # Helpers
tests/                  # 258 tests across 14 modules
examples/               # 5 runnable examples
```

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Examples

| Example | What it demonstrates |
|---------|---------------------|
| `basic_usage.py` | Init, unseal, write/read secrets |
| `policy_management.py` | RBAC with custom policies |
| `secret_rotation.py` | Versioning, soft-delete, destroy |
| `audit_trail.py` | Hash-chained audit log + verification |
| `envelope_encryption.py` | Low-level crypto internals |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/v1/sys/health` | Health check |
| POST | `/v1/sys/init` | Initialize vault |
| POST | `/v1/sys/unseal` | Provide unseal share |
| POST | `/v1/sys/seal` | Seal vault |
| GET | `/v1/sys/seal-status` | Seal status |
| POST | `/v1/secret/data/{path}` | Write secret |
| GET | `/v1/secret/data/{path}` | Read secret |
| DELETE | `/v1/secret/data/{path}` | Delete secret |
| GET | `/v1/secret/metadata/{path}` | Version history |
| POST | `/v1/auth/token/create` | Create token |
| POST | `/v1/auth/token/revoke` | Revoke token |
| GET | `/v1/auth/token/lookup` | Token info |
| PUT | `/v1/sys/policy/{name}` | Create policy |
| GET | `/v1/sys/audit` | Audit log |

## License

MIT
