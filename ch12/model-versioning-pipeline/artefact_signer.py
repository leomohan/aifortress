"""
artefact_signer.py  —  Cryptographic model artefact signing
AI Fortress · Chapter 12 · Code Sample 12.A

Signs model artefact bytes with HMAC-SHA256 and produces a
SignedArtefact record. Verification confirms both the content
digest (integrity) and the HMAC signature (authenticity).

In production, replace HMAC-SHA256 with asymmetric signing
(e.g. Ed25519 via the cryptography library) so the signing key
can be kept in a HSM while verification uses the public key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class SignedArtefact:
    artefact_id:  str
    model_name:   str
    version:      str
    sha256:       str       # hex digest of artefact bytes
    algorithm:    str       # "hmac-sha256"
    signature:    str       # hex HMAC over sha256 digest
    signer:       str
    signed_at:    str
    size_bytes:   int

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )


@dataclass
class VerificationResult:
    valid:         bool
    model_name:    str
    version:       str
    artefact_id:   str
    digest_ok:     bool   # content hash matches
    signature_ok:  bool   # HMAC matches
    reason:        str


class ArtefactSigner:
    """
    Signs and verifies model artefacts.

    Parameters
    ----------
    signing_key : Secret key bytes for HMAC-SHA256. In production,
                  load from a secrets manager, never hard-code.
    signer      : Identity string recorded in the signed artefact.
    """

    def __init__(self, signing_key: bytes, signer: str = "ai-fortress-signer"):
        if len(signing_key) < 32:
            raise ValueError("Signing key must be at least 32 bytes.")
        self._key    = signing_key
        self._signer = signer

    def sign(
        self,
        artefact_bytes: bytes,
        model_name:     str,
        version:        str,
    ) -> SignedArtefact:
        """Compute SHA-256 digest and HMAC-SHA256 signature for artefact bytes."""
        sha256    = hashlib.sha256(artefact_bytes).hexdigest()
        signature = hmac.new(self._key, sha256.encode(), hashlib.sha256).hexdigest()

        return SignedArtefact(
            artefact_id = str(uuid.uuid4()),
            model_name  = model_name,
            version     = version,
            sha256      = sha256,
            algorithm   = "hmac-sha256",
            signature   = signature,
            signer      = self._signer,
            signed_at   = datetime.now(timezone.utc).isoformat(),
            size_bytes  = len(artefact_bytes),
        )

    def verify(
        self,
        artefact_bytes: bytes,
        record:         SignedArtefact,
    ) -> VerificationResult:
        """Verify the integrity and authenticity of artefact bytes against a record."""
        computed_digest = hashlib.sha256(artefact_bytes).hexdigest()
        digest_ok       = hmac.compare_digest(computed_digest, record.sha256)

        expected_sig = hmac.new(self._key, record.sha256.encode(), hashlib.sha256).hexdigest()
        signature_ok = hmac.compare_digest(expected_sig, record.signature)

        valid  = digest_ok and signature_ok
        if not digest_ok:
            reason = "Content digest mismatch — artefact may have been tampered with."
        elif not signature_ok:
            reason = "Signature invalid — signing key mismatch or record corrupted."
        else:
            reason = "Artefact integrity and authenticity verified."

        return VerificationResult(
            valid        = valid,
            model_name   = record.model_name,
            version      = record.version,
            artefact_id  = record.artefact_id,
            digest_ok    = digest_ok,
            signature_ok = signature_ok,
            reason       = reason,
        )

    def verify_from_digest(
        self,
        claimed_digest: str,
        record:         SignedArtefact,
    ) -> VerificationResult:
        """
        Verify using a pre-computed digest string (e.g. from a remote manifest)
        without needing the full artefact bytes.
        """
        digest_ok    = hmac.compare_digest(claimed_digest, record.sha256)
        expected_sig = hmac.new(self._key, record.sha256.encode(), hashlib.sha256).hexdigest()
        signature_ok = hmac.compare_digest(expected_sig, record.signature)

        valid  = digest_ok and signature_ok
        reason = "Verified from digest." if valid else (
            "Digest mismatch." if not digest_ok else "Signature invalid."
        )
        return VerificationResult(
            valid=valid, model_name=record.model_name, version=record.version,
            artefact_id=record.artefact_id, digest_ok=digest_ok,
            signature_ok=signature_ok, reason=reason,
        )
