"""
provenance.py  —  Provenance record creation, signing, and single-record verification
AI Fortress · Chapter 1 · Code Sample 1.C

Provenance record (JSON):
  record_id           UUID4 — unique record identifier
  schema_version      "1.0"
  artifact_path       path or URI of the artifact
  artifact_sha256     hex SHA-256 of the artifact file
  pipeline_stage      e.g. "ingest" | "transform" | "tokenise" | "validate"
  signer_fingerprint  hex SHA-256 of signer's raw Ed25519 public key bytes
  signed_at           ISO-8601 UTC
  source_uri          where the artifact originated
  transformation      human-readable description of what was done
  parent_record_id    "" for root records; UUID4 of the parent provenance record
  signature           base64url Ed25519 signature over canonical JSON (all fields except signature)
"""
from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

SCHEMA_VERSION = "1.0"


@dataclass
class ProvenanceRecord:
    record_id:          str
    schema_version:     str
    artifact_path:      str
    artifact_sha256:    str
    pipeline_stage:     str
    signer_fingerprint: str
    signed_at:          str
    source_uri:         str
    transformation:     str
    parent_record_id:   str   # "" for root
    signature:          str   # base64url Ed25519 sig; "" before signing

    @property
    def is_root(self) -> bool:
        return self.parent_record_id == ""

    def canonical_bytes(self) -> bytes:
        """All fields except 'signature', sorted keys, compact JSON — deterministic."""
        d = asdict(self)
        d.pop("signature")
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

    def save(self, path: Path) -> None:
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def from_json(cls, text: str) -> "ProvenanceRecord":
        return cls(**json.loads(text))

    @classmethod
    def load(cls, path: Path) -> "ProvenanceRecord":
        return cls.from_json(path.read_text(encoding="utf-8"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def key_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


# ── Sign / Verify ─────────────────────────────────────────────────────────────

def sign_artifact(
    artifact_path:    Path,
    pipeline_stage:   str,
    private_key:      Ed25519PrivateKey,
    public_key:       Ed25519PublicKey,
    source_uri:       str = "",
    transformation:   str = "",
    parent_record_id: str = "",
) -> ProvenanceRecord:
    """Create and sign a provenance record for an artifact."""
    record = ProvenanceRecord(
        record_id          = str(uuid.uuid4()),
        schema_version     = SCHEMA_VERSION,
        artifact_path      = str(artifact_path),
        artifact_sha256    = file_sha256(artifact_path),
        pipeline_stage     = pipeline_stage,
        signer_fingerprint = key_fingerprint(public_key),
        signed_at          = datetime.now(timezone.utc).isoformat(),
        source_uri         = source_uri,
        transformation     = transformation,
        parent_record_id   = parent_record_id,
        signature          = "",
    )
    sig_bytes     = private_key.sign(record.canonical_bytes())
    record.signature = base64.urlsafe_b64encode(sig_bytes).decode("ascii")
    return record


def verify_record(record: ProvenanceRecord, public_key: Ed25519PublicKey) -> bool:
    """
    Verify a single provenance record.
    Returns True on success; raises cryptography.exceptions.InvalidSignature on failure.
    """
    sig_bytes = base64.urlsafe_b64decode(record.signature)
    public_key.verify(sig_bytes, record.canonical_bytes())  # raises on failure
    return True


def provenance_path_for(artifact_path: Path) -> Path:
    """Convention: <artifact>.provenance.json"""
    return artifact_path.parent / (artifact_path.name + ".provenance.json")
