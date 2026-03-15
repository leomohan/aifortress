"""
artefact_signer.py  —  Ed25519 artefact signing for CI/CD outputs
AI Fortress · Chapter 8 · Code Sample 8.D

Signs ML build artefacts with Ed25519 and produces:
  - A detached .sig file (binary Ed25519 signature)
  - A cosign-compatible bundle JSON for registry upload
  - A verification function for downstream consumers

Integrates with the SLSA provenance generator: the artefact SHA-256
recorded in the provenance statement is also the payload that is signed.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


@dataclass
class ArtefactSignature:
    artefact_name:  str
    artefact_sha256: str
    signature_hex:  str
    signer_id:      str
    public_key_pem: str
    signed_at:      str
    bundle_id:      str

    def save_sig(self, path: str | Path) -> None:
        Path(path).write_bytes(bytes.fromhex(self.signature_hex))

    def save_bundle(self, path: str | Path) -> None:
        """Save a cosign-compatible bundle JSON."""
        bundle = {
            "base64Sig": self.signature_hex,
            "cert":      self.public_key_pem,
            "payload": {
                "name":      self.artefact_name,
                "sha256":    self.artefact_sha256,
                "signer_id": self.signer_id,
                "signed_at": self.signed_at,
                "bundle_id": self.bundle_id,
            },
        }
        Path(path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")

    def verify(self, artefact_sha256: str) -> bool:
        """Verify this signature against an artefact SHA-256."""
        try:
            pub_key = serialization.load_pem_public_key(self.public_key_pem.encode())
            payload = artefact_sha256.encode("utf-8")
            pub_key.verify(bytes.fromhex(self.signature_hex), payload)
            return self.artefact_sha256 == artefact_sha256
        except InvalidSignature:
            return False
        except Exception:
            return False


class ArtefactSigner:
    """
    Signs ML build artefacts with Ed25519.

    Parameters
    ----------
    private_key : Ed25519PrivateKey (generate with Ed25519PrivateKey.generate())
    signer_id   : Human-readable identity for the signing entity
    """

    def __init__(
        self,
        private_key: Optional[Ed25519PrivateKey] = None,
        signer_id:   str = "ci-build-signer",
    ):
        self._key     = private_key or Ed25519PrivateKey.generate()
        self.signer_id = signer_id

    @classmethod
    def from_new_keypair(cls, signer_id: str = "ci-build-signer") -> "ArtefactSigner":
        return cls(Ed25519PrivateKey.generate(), signer_id=signer_id)

    def sign_file(self, path: str | Path, name: Optional[str] = None) -> ArtefactSignature:
        """Sign a file by its SHA-256 digest."""
        path = Path(path)
        sha256 = self._hash_file(path)
        return self.sign_digest(sha256, name=name or path.name)

    def sign_digest(self, sha256: str, name: str = "") -> ArtefactSignature:
        """Sign an artefact SHA-256 digest directly."""
        payload   = sha256.encode("utf-8")
        sig_bytes = self._key.sign(payload)
        pub_pem   = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return ArtefactSignature(
            artefact_name   = name,
            artefact_sha256 = sha256,
            signature_hex   = sig_bytes.hex(),
            signer_id       = self.signer_id,
            public_key_pem  = pub_pem,
            signed_at       = datetime.now(timezone.utc).isoformat(),
            bundle_id       = str(uuid.uuid4()),
        )

    def public_key_pem(self) -> str:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
