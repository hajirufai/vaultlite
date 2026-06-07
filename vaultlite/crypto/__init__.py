"""Cryptographic primitives — all implemented from scratch or using stdlib only."""

from vaultlite.crypto.aes import AES128
from vaultlite.crypto.modes import encrypt_cbc, decrypt_cbc
from vaultlite.crypto.padding import pkcs7_pad, pkcs7_unpad
from vaultlite.crypto.kdf import derive_key, generate_salt
from vaultlite.crypto.mac import hmac_sign, hmac_verify
from vaultlite.crypto.envelope import EnvelopeEncryption

__all__ = [
    "AES128",
    "encrypt_cbc",
    "decrypt_cbc",
    "pkcs7_pad",
    "pkcs7_unpad",
    "derive_key",
    "generate_salt",
    "hmac_sign",
    "hmac_verify",
    "EnvelopeEncryption",
]
