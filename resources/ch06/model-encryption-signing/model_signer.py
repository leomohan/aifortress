"""
model_signer.py  —  Ed25519 signing and signature manifest
AI Fortress · Chapter 6 · Code Sample 6.A

Signs model artefacts with Ed25519:
  - Produces a detached signature over SHA-256(file) + metadata JSON
  - Writes a SignatureManifest JSON alongside the artefact
  - Supports signing chains: a model signed by trainer, then countersigned
    by a governance reviewer before deployment
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


@dataclass
class SignatureEntry:
    signer_id:    str
    role:         str          # "trainer" | "reviewer" | "deployer"
    signature:    str          # hex-encoded Ed25519 signature
    signed_at:    str
    public_key:   str          # PEM-encoded public key
    metadata:     dict = field(default_factory=dict)


@dataclass
class SignatureManifest:
    manifest_id:   str
    artefact_path: str
    artefact_sha256: str
    artefact_size:  int
    model_name:    str
    model_version: str
    signatures:    List[SignatureEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "SignatureManifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        data["signatures"] = [SignatureEntry(**s) for s in data.get("signatures", [])]
        return cls(**data)


class ModelSigner:
    """
    Signs model artefacts with an Ed25519 private key.

    Parameters
    ----------
    private_key : Ed25519PrivateKey instance
    signer_id   : Human-readable identifier for the signing entity
    role        : Role in the signing chain ("trainer" | "reviewer" | "deployer")
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        signer_id:   str = "default-signer",
        role:        str = "trainer",
    ):
        self._private_key = private_key
        self.signer_id    = signer_id
        self.role         = role

    @classmethod
    def from_new_keypair(cls, signer_id: str = "default-signer", role: str = "trainer") -> "ModelSigner":
        """Generate a fresh Ed25519 keypair and return a ModelSigner instance."""
        private_key = Ed25519PrivateKey.generate()
        return cls(private_key, signer_id=signer_id, role=role)

    @classmethod
    def from_private_key_pem(cls, pem: bytes, signer_id: str = "default", role: str = "trainer") -> "ModelSigner":
        private_key = serialization.load_pem_private_key(pem, password=None)
        return cls(private_key, signer_id=signer_id, role=role)

    def public_key_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def save_keypair(self, private_path: str | Path, public_path: str | Path) -> None:
        Path(private_path).write_bytes(self.private_key_pem())
        Path(public_path).write_bytes(self.public_key_pem())

    def sign(
        self,
        artefact_path: str | Path,
        model_name:    str = "",
        model_version: str = "",
        metadata:      dict = {},
        manifest_path: Optional[str | Path] = None,
    ) -> SignatureManifest:
        """
        Sign `artefact_path` and write/update a SignatureManifest.

        If `manifest_path` already exists (prior signature), this adds a
        countersignature entry to the existing manifest.
        """
        artefact_path = Path(artefact_path)
        if manifest_path is None:
            manifest_path = artefact_path.with_suffix(artefact_path.suffix + ".manifest.json")
        manifest_path = Path(manifest_path)

        sha256, size = self._hash_file(artefact_path)

        # Load or create manifest
        if manifest_path.exists():
            manifest = SignatureManifest.load(manifest_path)
            if manifest.artefact_sha256 != sha256:
                raise ValueError(
                    f"Artefact SHA-256 has changed since first signature! "
                    f"Manifest: {manifest.artefact_sha256}, current: {sha256}"
                )
        else:
            manifest = SignatureManifest(
                manifest_id     = str(uuid.uuid4()),
                artefact_path   = str(artefact_path.resolve()),
                artefact_sha256 = sha256,
                artefact_size   = size,
                model_name      = model_name,
                model_version   = model_version,
            )

        # Payload to sign: sha256 + manifest_id + role + timestamp
        signed_at = datetime.now(timezone.utc).isoformat()
        payload   = json.dumps({
            "artefact_sha256": sha256,
            "manifest_id":     manifest.manifest_id,
            "signer_id":       self.signer_id,
            "role":            self.role,
            "signed_at":       signed_at,
            "metadata":        metadata,
        }, sort_keys=True).encode("utf-8")

        signature_bytes = self._private_key.sign(payload)

        entry = SignatureEntry(
            signer_id  = self.signer_id,
            role       = self.role,
            signature  = signature_bytes.hex(),
            signed_at  = signed_at,
            public_key = self.public_key_pem().decode("utf-8"),
            metadata   = metadata,
        )
        manifest.signatures.append(entry)
        manifest.save(manifest_path)
        return manifest

    @staticmethod
    def _hash_file(path: Path) -> tuple[str, int]:
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size
