"""
licence_enforcer.py  —  Licence policy embedding and enforcement
AI Fortress · Chapter 6 · Code Sample 6.C

Embeds a signed licence policy into a model artefact (as a sidecar JSON)
and verifies compliance at load time.  Raises LicenceViolationError if:
  - The licence has expired
  - The deployment environment (hostname/IP) is not in the permitted list
  - The use scope (inference-only, fine-tune-allowed, commercial) is violated
  - The licence signature is invalid (tampering detected)
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


class LicenceViolationError(RuntimeError):
    pass


@dataclass
class LicencePolicy:
    licence_id:          str
    model_name:          str
    model_version:       str
    licensee_id:         str
    issued_at:           str
    expires_at:          str            # ISO timestamp; "" = no expiry
    permitted_scopes:    List[str]      # e.g. ["inference", "research"]
    permitted_hostnames: List[str]      # allowed deployment hostnames; [] = any
    max_deployments:     int            # 0 = unlimited
    signature:           str            # Ed25519 hex signature over policy fields
    issuer_public_key:   str            # PEM for offline verification

    def to_dict(self) -> dict:
        return self.__dict__.copy()

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "LicencePolicy":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


class LicenceIssuer:
    """Issues signed licence policies."""

    def __init__(self, private_key: Optional[Ed25519PrivateKey] = None):
        if private_key is None:
            private_key = Ed25519PrivateKey.generate()
        self._key = private_key

    def issue(
        self,
        model_name:          str,
        model_version:       str,
        licensee_id:         str,
        permitted_scopes:    List[str],
        expires_at:          str = "",
        permitted_hostnames: List[str] = [],
        max_deployments:     int = 0,
    ) -> LicencePolicy:
        issued_at  = datetime.now(timezone.utc).isoformat()
        licence_id = "lic_" + uuid.uuid4().hex[:16]

        policy_fields = {
            "licence_id":          licence_id,
            "model_name":          model_name,
            "model_version":       model_version,
            "licensee_id":         licensee_id,
            "issued_at":           issued_at,
            "expires_at":          expires_at,
            "permitted_scopes":    permitted_scopes,
            "permitted_hostnames": permitted_hostnames,
            "max_deployments":     max_deployments,
        }
        payload    = json.dumps(policy_fields, sort_keys=True).encode("utf-8")
        sig_bytes  = self._key.sign(payload)
        pub_pem    = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        return LicencePolicy(
            **policy_fields,
            signature          = sig_bytes.hex(),
            issuer_public_key  = pub_pem,
        )


class LicenceEnforcer:
    """
    Verifies licence compliance at model load time.

    Parameters
    ----------
    use_scope : The scope the caller is attempting to use (e.g. "inference")
    """

    def __init__(self, use_scope: str = "inference"):
        self.use_scope = use_scope

    def enforce(self, policy: LicencePolicy) -> None:
        """
        Verify the licence policy. Raises LicenceViolationError on any violation.
        """
        errors: List[str] = []

        # ── Signature verification ────────────────────────────────────────
        try:
            from cryptography.hazmat.primitives import serialization as ser
            pub_key = ser.load_pem_public_key(policy.issuer_public_key.encode("utf-8"))
            policy_fields = {k: v for k, v in policy.to_dict().items()
                             if k not in ("signature", "issuer_public_key")}
            payload = json.dumps(policy_fields, sort_keys=True).encode("utf-8")
            pub_key.verify(bytes.fromhex(policy.signature), payload)
        except Exception as e:
            errors.append(f"Licence signature invalid: {e}")

        # ── Expiry ────────────────────────────────────────────────────────
        now = datetime.now(timezone.utc).isoformat()
        if policy.expires_at and now > policy.expires_at:
            errors.append(
                f"Licence expired at {policy.expires_at} (current: {now}). "
                "Contact the model issuer for renewal."
            )

        # ── Scope ─────────────────────────────────────────────────────────
        if self.use_scope not in policy.permitted_scopes:
            errors.append(
                f"Use scope '{self.use_scope}' not permitted. "
                f"Allowed scopes: {policy.permitted_scopes}."
            )

        # ── Hostname ──────────────────────────────────────────────────────
        if policy.permitted_hostnames:
            try:
                current_host = socket.gethostname()
            except Exception:
                current_host = "unknown"
            if current_host not in policy.permitted_hostnames:
                errors.append(
                    f"Deployment host '{current_host}' not in permitted hostnames: "
                    f"{policy.permitted_hostnames}."
                )

        if errors:
            raise LicenceViolationError(
                f"Licence violation for model '{policy.model_name}' "
                f"(licence {policy.licence_id}):\n  " + "\n  ".join(errors)
            )
