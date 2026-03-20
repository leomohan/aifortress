"""
envelope_key.py  —  DEK generation and KEK envelope operations
AI Fortress · Chapter 1 · Code Sample 1.A

Supports two key-management backends:
  kms   — AWS KMS  (GenerateDataKey / Decrypt / Encrypt)
  vault — HashiCorp Vault Transit secrets engine

The DEK (Data Encryption Key) is a 256-bit AES key that encrypts the dataset.
It is wrapped (encrypted) by a KEK (Key Encryption Key) that lives in KMS or
Vault and is NEVER written to disk in plaintext.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeyBackend(str, Enum):
    KMS   = "kms"
    VAULT = "vault"


@dataclass
class WrappedKey:
    """Serialisable envelope: wrapped DEK ciphertext + backend metadata."""
    backend:          str   # "kms" | "vault"
    wrapped_dek_b64:  str   # base64-encoded ciphertext of the DEK
    kms_key_id:       str = ""
    vault_key_name:   str = ""
    vault_key_version: int = 0

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, data: str) -> "WrappedKey":
        return cls(**json.loads(data))


# ── KMS ───────────────────────────────────────────────────────────────────────

def _kms_generate_dek(kms_key_id: str) -> Tuple[bytes, WrappedKey]:
    import boto3
    client   = boto3.client("kms")
    response = client.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
    plaintext_dek = response["Plaintext"]       # 32 bytes — use then discard
    wrapped_dek   = response["CiphertextBlob"]
    wk = WrappedKey(
        backend="kms",
        wrapped_dek_b64=base64.b64encode(wrapped_dek).decode(),
        kms_key_id=kms_key_id,
    )
    return plaintext_dek, wk


def _kms_unwrap_dek(wk: WrappedKey) -> bytes:
    import boto3
    client   = boto3.client("kms")
    response = client.decrypt(
        CiphertextBlob=base64.b64decode(wk.wrapped_dek_b64),
        KeyId=wk.kms_key_id,
    )
    return response["Plaintext"]


def _kms_rewrap_dek(wk: WrappedKey, new_kms_key_id: str) -> Tuple[bytes, WrappedKey]:
    import boto3
    plaintext_dek = _kms_unwrap_dek(wk)
    client   = boto3.client("kms")
    response = client.encrypt(KeyId=new_kms_key_id, Plaintext=plaintext_dek)
    new_wk = WrappedKey(
        backend="kms",
        wrapped_dek_b64=base64.b64encode(response["CiphertextBlob"]).decode(),
        kms_key_id=new_kms_key_id,
    )
    return plaintext_dek, new_wk


# ── Vault ─────────────────────────────────────────────────────────────────────

def _vault_generate_dek(vault_key_name: str) -> Tuple[bytes, WrappedKey]:
    import hvac
    plaintext_dek = AESGCM.generate_key(bit_length=256)
    client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
    resp   = client.secrets.transit.encrypt_data(
        name=vault_key_name,
        plaintext=base64.b64encode(plaintext_dek).decode(),
    )
    ciphertext  = resp["data"]["ciphertext"]
    key_version = int(resp["data"].get("key_version", 1))
    wk = WrappedKey(
        backend="vault",
        wrapped_dek_b64=base64.b64encode(ciphertext.encode()).decode(),
        vault_key_name=vault_key_name,
        vault_key_version=key_version,
    )
    return plaintext_dek, wk


def _vault_unwrap_dek(wk: WrappedKey) -> bytes:
    import hvac
    client     = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
    ciphertext = base64.b64decode(wk.wrapped_dek_b64).decode()
    resp       = client.secrets.transit.decrypt_data(name=wk.vault_key_name, ciphertext=ciphertext)
    return base64.b64decode(resp["data"]["plaintext"])


# ── Public API ────────────────────────────────────────────────────────────────

def generate_dek(
    backend:        KeyBackend,
    kms_key_id:     str = "",
    vault_key_name: str = "",
) -> Tuple[bytes, WrappedKey]:
    """Generate a new DEK. Returns (plaintext_dek, wrapped_key). Discard plaintext_dek after use."""
    if backend == KeyBackend.KMS:
        if not kms_key_id:
            raise ValueError("kms_key_id required for KMS backend")
        return _kms_generate_dek(kms_key_id)
    if backend == KeyBackend.VAULT:
        if not vault_key_name:
            raise ValueError("vault_key_name required for Vault backend")
        return _vault_generate_dek(vault_key_name)
    raise ValueError(f"Unknown backend: {backend}")


def unwrap_dek(wk: WrappedKey) -> bytes:
    """Unwrap and return plaintext DEK. Discard after use."""
    if wk.backend == KeyBackend.KMS:
        return _kms_unwrap_dek(wk)
    if wk.backend == KeyBackend.VAULT:
        return _vault_unwrap_dek(wk)
    raise ValueError(f"Unknown backend: {wk.backend}")


def rewrap_dek(wk: WrappedKey, new_kms_key_id: str) -> Tuple[bytes, WrappedKey]:
    """Re-wrap DEK under a new KMS key (key rotation). KMS backend only."""
    if wk.backend != KeyBackend.KMS:
        raise NotImplementedError(
            "rewrap_dek is KMS-only. For Vault use the Transit rewrap endpoint."
        )
    return _kms_rewrap_dek(wk, new_kms_key_id)
