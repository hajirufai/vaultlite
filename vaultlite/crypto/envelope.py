"""Envelope encryption — the standard pattern for managing many secrets.

Instead of encrypting every secret with the master key directly,
envelope encryption generates a unique Data Encryption Key (DEK)
for each secret. The DEK encrypts the data, then the DEK itself
is encrypted (wrapped) by the master Key Encryption Key (KEK).

Benefits:
- Rotating the master key only requires re-wrapping DEKs, not
  re-encrypting all data.
- Compromise of one DEK doesn't expose other secrets.
- DEKs can be cached in memory while the KEK stays protected.

Flow:
    Encrypt: data --[DEK]--> ciphertext, DEK --[KEK]--> wrapped_dek
    Decrypt: wrapped_dek --[KEK]--> DEK, ciphertext --[DEK]--> data
"""

from __future__ import annotations

import base64
import json
import os

from vaultlite.crypto.aes import AES128, BLOCK_SIZE
from vaultlite.crypto.modes import encrypt_cbc, decrypt_cbc
from vaultlite.crypto.mac import hmac_sign, hmac_verify
from vaultlite.errors import CryptoError
from vaultlite.types import EncryptedPayload


class EnvelopeEncryption:
    """Envelope encryption using AES-128-CBC with HMAC-SHA256.

    Each encryption operation generates a fresh random DEK. The DEK
    encrypts the data (AES-CBC), then the DEK is wrapped by the
    master key (also AES-CBC). An HMAC covers everything for
    tamper detection.

    Example:
        envelope = EnvelopeEncryption(master_key=os.urandom(16))
        payload = envelope.encrypt(b"database_password=hunter2")
        plaintext = envelope.decrypt(payload)
    """

    def __init__(self, master_key: bytes):
        """Initialize with a 16-byte master key (KEK).

        Args:
            master_key: The Key Encryption Key. 16 bytes for AES-128.
        """
        if len(master_key) != BLOCK_SIZE:
            raise CryptoError(
                f"Master key must be {BLOCK_SIZE} bytes, got {len(master_key)}"
            )
        self._kek = master_key
        self._kek_aes = AES128(master_key)

    def encrypt(self, plaintext: bytes) -> EncryptedPayload:
        """Encrypt data using envelope encryption.

        1. Generate random DEK (16 bytes)
        2. Encrypt plaintext with DEK (AES-128-CBC)
        3. Wrap DEK with KEK (AES-128-CBC)
        4. HMAC-SHA256 over IV + ciphertext + wrapped_dek

        Args:
            plaintext: Data to encrypt.

        Returns:
            EncryptedPayload with all components base64/hex encoded.
        """
        # Step 1: Generate random Data Encryption Key
        dek = os.urandom(BLOCK_SIZE)
        dek_aes = AES128(dek)

        # Step 2: Encrypt plaintext with DEK
        iv = os.urandom(BLOCK_SIZE)
        encrypted_data = encrypt_cbc(dek_aes, plaintext, iv=iv)
        # encrypted_data includes IV prepended — extract separately
        actual_iv = encrypted_data[:BLOCK_SIZE]
        ciphertext = encrypted_data[BLOCK_SIZE:]

        # Step 3: Wrap DEK with KEK
        dek_iv = os.urandom(BLOCK_SIZE)
        wrapped_dek = encrypt_cbc(self._kek_aes, dek, iv=dek_iv)

        # Step 4: HMAC over all components
        mac_data = actual_iv + ciphertext + wrapped_dek
        mac = hmac_sign(self._kek, mac_data)

        return EncryptedPayload(
            ciphertext=base64.b64encode(ciphertext).decode("ascii"),
            iv=base64.b64encode(actual_iv).decode("ascii"),
            hmac=mac,
            encrypted_dek=base64.b64encode(wrapped_dek).decode("ascii"),
        )

    def decrypt(self, payload: EncryptedPayload) -> bytes:
        """Decrypt an envelope-encrypted payload.

        1. Verify HMAC (reject tampered data before decrypting)
        2. Unwrap DEK with KEK
        3. Decrypt ciphertext with DEK

        Args:
            payload: The EncryptedPayload from a previous encrypt() call.

        Returns:
            Original plaintext bytes.

        Raises:
            CryptoError: If HMAC verification fails (data tampered).
        """
        # Decode components
        ciphertext = base64.b64decode(payload.ciphertext)
        iv = base64.b64decode(payload.iv)
        wrapped_dek = base64.b64decode(payload.encrypted_dek)

        # Step 1: Verify HMAC before any decryption
        mac_data = iv + ciphertext + wrapped_dek
        if not hmac_verify(self._kek, mac_data, payload.hmac):
            raise CryptoError("HMAC verification failed — data may be tampered")

        # Step 2: Unwrap DEK
        dek = decrypt_cbc(self._kek_aes, wrapped_dek)

        # Step 3: Decrypt data with DEK
        dek_aes = AES128(dek)
        full_data = iv + ciphertext
        return decrypt_cbc(dek_aes, full_data)

    def rotate_master_key(
        self, new_master_key: bytes, payloads: list[EncryptedPayload]
    ) -> list[EncryptedPayload]:
        """Re-wrap all DEKs with a new master key.

        The actual data is NOT re-encrypted — only the DEK wrappers change.
        This is the key benefit of envelope encryption.

        Args:
            new_master_key: The new KEK (16 bytes).
            payloads: List of existing encrypted payloads.

        Returns:
            New payloads with DEKs re-wrapped under the new master key.
        """
        new_kek_aes = AES128(new_master_key)
        rotated = []

        for payload in payloads:
            # Unwrap DEK with old KEK
            wrapped_dek = base64.b64decode(payload.encrypted_dek)
            ciphertext = base64.b64decode(payload.ciphertext)
            iv = base64.b64decode(payload.iv)

            # Verify old HMAC
            mac_data = iv + ciphertext + wrapped_dek
            if not hmac_verify(self._kek, mac_data, payload.hmac):
                raise CryptoError("HMAC verification failed during key rotation")

            dek = decrypt_cbc(self._kek_aes, wrapped_dek)

            # Re-wrap DEK with new KEK
            new_dek_iv = os.urandom(BLOCK_SIZE)
            new_wrapped_dek = encrypt_cbc(new_kek_aes, dek, iv=new_dek_iv)

            # Compute new HMAC
            new_mac_data = iv + ciphertext + new_wrapped_dek
            new_mac = hmac_sign(new_master_key, new_mac_data)

            rotated.append(EncryptedPayload(
                ciphertext=payload.ciphertext,
                iv=payload.iv,
                hmac=new_mac,
                encrypted_dek=base64.b64encode(new_wrapped_dek).decode("ascii"),
            ))

        return rotated
