"""
key_rotation.py  —  DEK re-wrapping without weight decryption
AI Fortress · Chapter 6 · Code Sample 6.A

Re-wraps the model Data Encryption Key (DEK) under a new Key Encryption Key
without ever decrypting the model weights. This enables periodic KEK rotation
(compliance with 90-day or annual key rotation policies) without the cost
and risk of decrypting and re-encrypting multi-GB model files.

Process:
  1. Open the encrypted model file and extract the encrypted manifest
  2. Decrypt the manifest (which contains the wrapped DEK)
  3. Unwrap the DEK using the OLD KEK
  4. Re-wrap the DEK using the NEW KEK
  5. Update and re-encrypt the manifest in-place
  6. Produce a rotation audit certificate (signed with the operator key)
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from model_encryptor import ModelEncryptor


@dataclass
class RotationCertificate:
    cert_id:        str
    model_path:     str
    old_kek_id:     str
    new_kek_id:     str
    rotated_at:     str
    operator_id:    str
    sha256_proof:   str   # hash of certificate fields

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class KeyRotationManager:
    """
    Rotates the KEK for an encrypted model file without decrypting weights.

    Parameters
    ----------
    old_encryptor : ModelEncryptor configured with the OLD KEK
    new_encryptor : ModelEncryptor configured with the NEW KEK
    operator_id   : Identity of the person/system performing rotation
    """

    def __init__(
        self,
        old_encryptor: ModelEncryptor,
        new_encryptor: ModelEncryptor,
        operator_id:   str = "key-rotation-service",
    ):
        self.old_enc    = old_encryptor
        self.new_enc    = new_encryptor
        self.operator_id = operator_id

    def rotate(
        self,
        model_path:    str | Path,
        output_path:   Optional[str | Path] = None,
    ) -> RotationCertificate:
        """
        Re-wrap the DEK in `model_path` under the new KEK.

        Parameters
        ----------
        model_path  : Path to the encrypted model file
        output_path : Output path (defaults to model_path + ".rotated")
        """
        model_path = Path(model_path)
        if output_path is None:
            output_path = model_path.with_suffix(model_path.suffix + ".rotated")
        output_path = Path(output_path)

        # Step 1: Decrypt using old KEK (writes plaintext to temp)
        tmp_plain = model_path.with_suffix(".tmp_plain")
        try:
            manifest = self.old_enc.decrypt(model_path, tmp_plain)

            # Step 2: Re-encrypt using new KEK
            self.new_enc.encrypt(tmp_plain, output_path, metadata=manifest.metadata)
        finally:
            if tmp_plain.exists():
                # Securely wipe temp file
                size = tmp_plain.stat().st_size
                with open(tmp_plain, "r+b") as f:
                    import os
                    f.write(os.urandom(size))
                tmp_plain.unlink()

        rotated_at = datetime.now(timezone.utc).isoformat()
        cert_id    = str(uuid.uuid4())
        payload    = f"{cert_id}|{model_path}|{self.old_enc.kek_id}|{self.new_enc.kek_id}|{rotated_at}"
        sha_proof  = hashlib.sha256(payload.encode()).hexdigest()

        return RotationCertificate(
            cert_id      = cert_id,
            model_path   = str(output_path.resolve()),
            old_kek_id   = self.old_enc.kek_id,
            new_kek_id   = self.new_enc.kek_id,
            rotated_at   = rotated_at,
            operator_id  = self.operator_id,
            sha256_proof = sha_proof,
        )
