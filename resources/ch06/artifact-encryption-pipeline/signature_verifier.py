"""
signature_verifier.py  —  Verification pipeline with chain support
AI Fortress · Chapter 6 · Code Sample 6.A
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from model_signer import SignatureManifest, SignatureEntry


@dataclass
class VerificationResult:
    valid:           bool
    artefact_sha256: str
    verified_signers: List[str]
    failed_signers:   List[str]
    errors:          List[str]
    model_name:      str
    model_version:   str


class SignatureVerifier:
    """
    Verifies Ed25519 signature manifests for model artefacts.

    Parameters
    ----------
    required_roles : If set, verification fails unless ALL roles are present.
                     E.g. ["trainer", "reviewer"] enforces a two-party signing chain.
    trusted_keys   : Optional mapping of signer_id → PEM public key bytes.
                     If provided, only signatures from trusted_keys are accepted.
    """

    def __init__(
        self,
        required_roles: Optional[List[str]] = None,
        trusted_keys:   Optional[dict] = None,   # signer_id → PEM bytes
    ):
        self.required_roles = required_roles or []
        self.trusted_keys   = trusted_keys or {}

    def verify(
        self,
        artefact_path:  str | Path,
        manifest_path:  Optional[str | Path] = None,
    ) -> VerificationResult:
        """
        Verify all signatures in the manifest against the artefact.
        Returns a VerificationResult; raises nothing — callers check .valid.
        """
        artefact_path = Path(artefact_path)
        if manifest_path is None:
            manifest_path = artefact_path.with_suffix(artefact_path.suffix + ".manifest.json")
        manifest_path = Path(manifest_path)

        errors: List[str] = []
        verified: List[str] = []
        failed:   List[str] = []

        # ── Manifest exists ───────────────────────────────────────────────
        if not manifest_path.exists():
            return VerificationResult(
                valid=False, artefact_sha256="", verified_signers=[],
                failed_signers=[], model_name="", model_version="",
                errors=["Signature manifest not found — artefact is unsigned."],
            )

        try:
            manifest = SignatureManifest.load(manifest_path)
        except Exception as e:
            return VerificationResult(
                valid=False, artefact_sha256="", verified_signers=[],
                failed_signers=[], model_name="", model_version="",
                errors=[f"Failed to load manifest: {e}"],
            )

        # ── Artefact hash check ───────────────────────────────────────────
        actual_sha256 = self._hash_file(artefact_path)
        if actual_sha256 != manifest.artefact_sha256:
            errors.append(
                f"Artefact SHA-256 mismatch! "
                f"Manifest: {manifest.artefact_sha256}, actual: {actual_sha256}. "
                "Artefact may have been tampered with."
            )
            return VerificationResult(
                valid=False, artefact_sha256=actual_sha256,
                verified_signers=[], failed_signers=[],
                model_name=manifest.model_name, model_version=manifest.model_version,
                errors=errors,
            )

        # ── Per-signature verification ────────────────────────────────────
        for entry in manifest.signatures:
            try:
                # Optionally enforce trusted key list
                if self.trusted_keys and entry.signer_id not in self.trusted_keys:
                    failed.append(entry.signer_id)
                    errors.append(f"Signer '{entry.signer_id}' not in trusted keys list.")
                    continue

                pub_key = serialization.load_pem_public_key(
                    entry.public_key.encode("utf-8")
                )
                payload = json.dumps({
                    "artefact_sha256": manifest.artefact_sha256,
                    "manifest_id":     manifest.manifest_id,
                    "signer_id":       entry.signer_id,
                    "role":            entry.role,
                    "signed_at":       entry.signed_at,
                    "metadata":        entry.metadata,
                }, sort_keys=True).encode("utf-8")

                pub_key.verify(bytes.fromhex(entry.signature), payload)
                verified.append(entry.signer_id)
            except InvalidSignature:
                failed.append(entry.signer_id)
                errors.append(f"INVALID signature from signer '{entry.signer_id}'.")
            except Exception as e:
                failed.append(entry.signer_id)
                errors.append(f"Error verifying signer '{entry.signer_id}': {e}")

        # ── Required roles check ──────────────────────────────────────────
        signed_roles = {e.role for e in manifest.signatures if e.signer_id in verified}
        for role in self.required_roles:
            if role not in signed_roles:
                errors.append(f"Required signing role '{role}' not present in verified signatures.")

        valid = len(failed) == 0 and len(errors) == 0 and len(verified) > 0

        return VerificationResult(
            valid            = valid,
            artefact_sha256  = actual_sha256,
            verified_signers = verified,
            failed_signers   = failed,
            model_name       = manifest.model_name,
            model_version    = manifest.model_version,
            errors           = errors,
        )

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
