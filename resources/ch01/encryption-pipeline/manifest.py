"""
manifest.py  —  Encrypted dataset manifest
AI Fortress · Chapter 1 · Code Sample 1.A

Each encrypted dataset artifact is accompanied by a <file>.manifest.enc that
records provenance metadata AND the wrapped DEK reference.  The manifest is
itself encrypted under a fresh DEK wrapped by the same KEK, so an attacker
reading the manifest file cannot extract the dataset's wrapped DEK without
access to the KEK.

On-disk format of the manifest file:
  [4 bytes big-endian]  length of wrapped-key JSON
  [N bytes UTF-8]       WrappedKey JSON  (manifest's own wrapped DEK)
  [12 bytes]            AES-GCM nonce
  [M bytes]             AES-GCM ciphertext of manifest JSON  (+ 16-byte tag)
"""
from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from envelope_key import WrappedKey, KeyBackend, generate_dek, unwrap_dek

MANIFEST_SCHEMA_VERSION = "1.0"


@dataclass
class DatasetManifest:
    schema_version:    str
    original_filename: str
    plaintext_sha256:  str
    encrypted_at:      str
    chunk_size:        int
    wrapped_key:       dict          # serialised WrappedKey for the dataset
    classification:    str = "CONFIDENTIAL"
    owner:             str = ""
    dataset_id:        str = ""
    notes:             str = ""


def create_manifest(
    original_path:    Path,
    plaintext_sha256: str,
    chunk_size:       int,
    wrapped_key:      WrappedKey,
    classification:   str = "CONFIDENTIAL",
    owner:            str = "",
    dataset_id:       str = "",
    notes:            str = "",
) -> DatasetManifest:
    return DatasetManifest(
        schema_version    = MANIFEST_SCHEMA_VERSION,
        original_filename = original_path.name,
        plaintext_sha256  = plaintext_sha256,
        encrypted_at      = datetime.now(timezone.utc).isoformat(),
        chunk_size        = chunk_size,
        wrapped_key       = asdict(wrapped_key),
        classification    = classification,
        owner             = owner,
        dataset_id        = dataset_id,
        notes             = notes,
    )


def save_manifest(
    manifest:       DatasetManifest,
    output_path:    Path,
    backend:        KeyBackend,
    kms_key_id:     str = "",
    vault_key_name: str = "",
) -> None:
    """Encrypt and write the manifest to output_path."""
    plaintext_dek, mf_wrapped_key = generate_dek(
        backend=backend, kms_key_id=kms_key_id, vault_key_name=vault_key_name,
    )
    payload    = json.dumps(asdict(manifest), indent=2).encode("utf-8")
    aesgcm     = AESGCM(plaintext_dek)
    nonce      = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, payload, None)
    wk_json    = mf_wrapped_key.to_json().encode("utf-8")

    with open(output_path, "wb") as f:
        f.write(struct.pack(">I", len(wk_json)))
        f.write(wk_json)
        f.write(nonce)
        f.write(ciphertext)


def load_manifest(manifest_path: Path) -> DatasetManifest:
    """Decrypt and deserialise a manifest file."""
    with open(manifest_path, "rb") as f:
        wk_len     = struct.unpack(">I", f.read(4))[0]
        wk_json    = f.read(wk_len).decode("utf-8")
        nonce      = f.read(12)
        ciphertext = f.read()

    mf_wk         = WrappedKey.from_json(wk_json)
    plaintext_dek = unwrap_dek(mf_wk)
    aesgcm        = AESGCM(plaintext_dek)
    payload       = aesgcm.decrypt(nonce, ciphertext, None)
    data          = json.loads(payload.decode("utf-8"))
    wk            = data.pop("wrapped_key")
    return DatasetManifest(**data, wrapped_key=wk)


def get_dataset_wrapped_key(manifest: DatasetManifest) -> WrappedKey:
    return WrappedKey(**manifest.wrapped_key)
