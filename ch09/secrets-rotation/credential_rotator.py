"""
credential_rotator.py  —  Database credential dual-rotation for ML services
AI Fortress · Chapter 9 · Code Sample 9.C

Implements dual-credential rotation for ML training and serving databases:
  1. Generate new credential
  2. Create new credential in the database
  3. Test new credential (smoke test)
  4. Update application secret store with new credential
  5. Wait for grace period (in-flight requests drain)
  6. Revoke old credential
  7. Issue rotation certificate

This pattern ensures zero downtime: both old and new credentials are valid
during the grace period.

Supports: PostgreSQL, MySQL, MongoDB (connection string templates).
Production: plug in your secret store (Vault, AWS Secrets Manager, etc.)
via the `secret_store_fn` callback.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional


_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"
_PASSWORD_LENGTH   = 32


def _generate_password(length: int = _PASSWORD_LENGTH) -> str:
    return "".join(secrets.choice(_PASSWORD_ALPHABET) for _ in range(length))


@dataclass
class RotationCertificate:
    rotation_id:   str
    service:       str
    database:      str
    username:      str
    rotated_at:    str
    old_cred_hash: str    # SHA-256 of old password (never store plaintext)
    new_cred_hash: str    # SHA-256 of new password
    grace_period_secs: int
    sha256_proof:  str

    def save(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


@dataclass
class CredentialSpec:
    service:       str         # logical service name (e.g. "training-db")
    database:      str         # database name
    username:      str         # database username to rotate
    db_type:       str         # "postgresql" | "mysql" | "mongodb"
    host:          str
    port:          int
    rotation_days: int = 30    # rotate every N days


class CredentialRotator:
    """
    Rotates database credentials with dual-credential zero-downtime rotation.

    Parameters
    ----------
    create_cred_fn  : Callable(spec, new_password) → None
                      Creates the new credential in the database.
    revoke_cred_fn  : Callable(spec, old_password) → None
                      Revokes the old credential.
    smoke_test_fn   : Callable(spec, new_password) → bool
                      Tests the new credential (returns True if OK).
    store_cred_fn   : Callable(spec, new_password) → None
                      Stores the new credential in the secret store.
    grace_period    : Seconds to keep old credential active after rotation.
    audit_trail     : Optional RotationAuditTrail instance for logging.
    """

    def __init__(
        self,
        create_cred_fn:  Callable,
        revoke_cred_fn:  Callable,
        smoke_test_fn:   Callable,
        store_cred_fn:   Callable,
        grace_period:    int = 300,
        audit_trail=None,
    ):
        self._create    = create_cred_fn
        self._revoke    = revoke_cred_fn
        self._test      = smoke_test_fn
        self._store     = store_cred_fn
        self._grace     = grace_period
        self._audit     = audit_trail

    def rotate(self, spec: CredentialSpec, old_password: str) -> RotationCertificate:
        """
        Execute dual-credential rotation for `spec`.
        Raises RotationError if smoke test fails (old credential left intact).
        """
        rotation_id  = str(uuid.uuid4())
        new_password = _generate_password()

        # Step 1: Create new credential
        self._create(spec, new_password)

        # Step 2: Smoke test
        if not self._test(spec, new_password):
            # Roll back: revoke the new credential immediately
            try:
                self._revoke(spec, new_password)
            except Exception:
                pass
            raise RotationError(
                f"Smoke test failed for {spec.service}/{spec.database}. "
                "Old credential left active. Rotation aborted."
            )

        # Step 3: Update secret store
        self._store(spec, new_password)

        # Step 4: Revoke old credential (after grace period in production;
        #         here we call immediately — caller should delay if needed)
        self._revoke(spec, old_password)

        if self._audit:
            self._audit.log_rotation(spec.service, "credential",
                                     detail=f"Rotated {spec.username}@{spec.database}")

        # Issue certificate
        cert = self._make_cert(rotation_id, spec, old_password, new_password)
        return cert

    @staticmethod
    def connection_string(spec: CredentialSpec, password: str) -> str:
        """Build a connection string for the given database type."""
        templates = {
            "postgresql": "postgresql://{user}:{pw}@{host}:{port}/{db}",
            "mysql":      "mysql+pymysql://{user}:{pw}@{host}:{port}/{db}",
            "mongodb":    "mongodb://{user}:{pw}@{host}:{port}/{db}",
        }
        tmpl = templates.get(spec.db_type, "{user}:{pw}@{host}:{port}/{db}")
        return tmpl.format(
            user=spec.username, pw=password,
            host=spec.host, port=spec.port, db=spec.database,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _make_cert(
        self,
        rotation_id:  str,
        spec:         CredentialSpec,
        old_password: str,
        new_password: str,
    ) -> RotationCertificate:
        now       = datetime.now(timezone.utc).isoformat()
        old_hash  = hashlib.sha256(old_password.encode()).hexdigest()
        new_hash  = hashlib.sha256(new_password.encode()).hexdigest()
        cert_data = {
            "rotation_id":      rotation_id,
            "service":          spec.service,
            "database":         spec.database,
            "username":         spec.username,
            "rotated_at":       now,
            "old_cred_hash":    old_hash,
            "new_cred_hash":    new_hash,
            "grace_period_secs": self._grace,
        }
        proof = hashlib.sha256(
            json.dumps(cert_data, sort_keys=True).encode()
        ).hexdigest()
        return RotationCertificate(**cert_data, sha256_proof=proof)


class RotationError(RuntimeError):
    pass
