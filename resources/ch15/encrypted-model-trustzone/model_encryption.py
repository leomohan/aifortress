"""
model_encryption.py  —  AES-256-GCM model artefact encryption
AI Fortress · Chapter 15 · Code Sample 15.B

Encrypts model weight files with AES-256-GCM for secure storage on
edge devices. The encryption key is derived from a device-specific
secret (e.g. eFuse or TPM-bound key) so the ciphertext is only
decryptable on the authorised device.

AES-GCM provides:
  - Confidentiality: encrypted with 256-bit key
  - Integrity: 128-bit authentication tag detects tampering
  - Authenticity: key binding to device prevents cross-device use

Production notes:
  - Key derivation: use HKDF(device_secret, "model-encryption", model_id)
  - Key storage: bind to TPM2_Seal or ARM TrustZone secure storage
  - Nonce: never reuse nonce with same key (use random 96-bit nonce per file)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


_TAG_SIZE   = 16   # GCM authentication tag size in bytes
_NONCE_SIZE = 12   # GCM nonce size (96 bits)
_KEY_SIZE   = 32   # AES-256 key size


@dataclass
class EncryptedModelPackage:
    model_id:    str
    nonce:       bytes
    ciphertext:  bytes
    auth_tag:    bytes      # GCM authentication tag (16 bytes)
    key_id:      str        # identifies which device key was used
    algorithm:   str        # "aes-256-gcm"
    plaintext_sha256: str   # SHA-256 of original plaintext for integrity check

    def to_bytes(self) -> bytes:
        """Serialise to binary: nonce || auth_tag || ciphertext"""
        return self.nonce + self.auth_tag + self.ciphertext

    def save(self, path: str | Path) -> None:
        meta = {
            "model_id": self.model_id, "key_id": self.key_id,
            "algorithm": self.algorithm, "plaintext_sha256": self.plaintext_sha256,
            "nonce": self.nonce.hex(), "auth_tag": self.auth_tag.hex(),
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2))
        p.write_bytes(self.to_bytes())


@dataclass
class DecryptionResult:
    success:      bool
    model_id:     str
    plaintext:    Optional[bytes]
    integrity_ok: bool    # SHA-256 of decrypted bytes matches original
    reason:       str


class ModelEncryptor:
    """
    Encrypts and decrypts ML model artefacts with AES-256-GCM.

    Uses a pure-Python XOR-stream + HMAC-based authenticated encryption
    simulation when the `cryptography` library is unavailable (tests).
    In production always use cryptography.hazmat AES-GCM.

    Parameters
    ----------
    key    : 32-byte AES-256 key.
    key_id : Identifier for the key (e.g. device serial or TPM key handle).
    """

    def __init__(self, key: bytes, key_id: str = "device-key-v1"):
        if len(key) != _KEY_SIZE:
            raise ValueError(f"key must be exactly {_KEY_SIZE} bytes (AES-256)")
        self._key    = key
        self._key_id = key_id

    def encrypt(self, plaintext: bytes, model_id: str) -> EncryptedModelPackage:
        """Encrypt model bytes. Returns an EncryptedModelPackage."""
        nonce      = os.urandom(_NONCE_SIZE)
        ciphertext = self._xor_stream(plaintext, nonce)
        auth_tag   = self._compute_tag(nonce, ciphertext, model_id.encode())
        pt_hash    = hashlib.sha256(plaintext).hexdigest()

        return EncryptedModelPackage(
            model_id         = model_id,
            nonce            = nonce,
            ciphertext       = ciphertext,
            auth_tag         = auth_tag,
            key_id           = self._key_id,
            algorithm        = "aes-256-gcm-sim",
            plaintext_sha256 = pt_hash,
        )

    def decrypt(
        self, package: EncryptedModelPackage
    ) -> DecryptionResult:
        """Decrypt and verify an EncryptedModelPackage."""
        # Verify authentication tag first
        expected_tag = self._compute_tag(
            package.nonce, package.ciphertext, package.model_id.encode()
        )
        if not hmac.compare_digest(expected_tag, package.auth_tag):
            return DecryptionResult(
                success=False, model_id=package.model_id,
                plaintext=None, integrity_ok=False,
                reason="Authentication tag invalid — ciphertext may be tampered.",
            )

        plaintext    = self._xor_stream(package.ciphertext, package.nonce)
        actual_hash  = hashlib.sha256(plaintext).hexdigest()
        integrity_ok = hmac.compare_digest(actual_hash, package.plaintext_sha256)

        return DecryptionResult(
            success      = True,
            model_id     = package.model_id,
            plaintext    = plaintext,
            integrity_ok = integrity_ok,
            reason       = "Decrypted successfully." if integrity_ok
                           else "Decrypted but plaintext hash mismatch.",
        )

    def _xor_stream(self, data: bytes, nonce: bytes) -> bytes:
        """
        Simulate AES-CTR: generate keystream via HMAC-SHA256 and XOR.
        This is NOT secure AES-GCM; use cryptography.hazmat in production.
        """
        out = bytearray()
        block, counter = 0, 0
        while len(out) < len(data):
            stream_block = hmac.new(
                self._key,
                nonce + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
            out.extend(stream_block)
            counter += 1
        return bytes(a ^ b for a, b in zip(data, out[:len(data)]))

    def _compute_tag(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Compute HMAC-SHA256(key, nonce || aad || ciphertext) as auth tag."""
        return hmac.new(
            self._key, nonce + aad + ciphertext, hashlib.sha256
        ).digest()[:_TAG_SIZE]
