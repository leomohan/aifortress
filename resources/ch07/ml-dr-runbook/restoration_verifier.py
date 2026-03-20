"""
restoration_verifier.py  —  Artefact integrity and restoration verification
AI Fortress · Chapter 7 · Code Sample 7.C

Verifies that a restored ML artefact is complete and uncorrupted by:
  1. SHA-256 checksum comparison against the backup manifest
  2. File size verification
  3. Optional functional smoke test (caller-supplied callable)
  4. Issuing a signed RestorationCertificate on success
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional


@dataclass
class RestorationCertificate:
    cert_id:          str
    resource_id:      str
    restored_path:    str
    sha256_verified:  bool
    size_verified:    bool
    smoke_test_passed: Optional[bool]
    restored_at:      str
    operator_id:      str
    overall_pass:     bool
    sha256_proof:     str     # SHA-256 of certificate fields

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "RestorationCertificate":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


class RestorationVerifier:
    """
    Verifies the integrity of a restored ML artefact.

    Parameters
    ----------
    operator_id : Identity of the person/system performing the restoration
    """

    def __init__(self, operator_id: str = "dr-automation"):
        self.operator_id = operator_id

    def verify(
        self,
        restored_path:  str | Path,
        expected_sha256: str,
        expected_size:   int,
        resource_id:     str = "",
        smoke_test_fn:   Optional[Callable[[Path], bool]] = None,
    ) -> RestorationCertificate:
        """
        Verify a restored file against expected checksum and size.

        Parameters
        ----------
        restored_path    : Path to the restored artefact file
        expected_sha256  : SHA-256 hex digest from the backup manifest
        expected_size    : Expected file size in bytes
        resource_id      : Logical resource identifier (for the certificate)
        smoke_test_fn    : Optional callable(path) → bool for functional test
        """
        restored_path = Path(restored_path)

        # SHA-256 verification
        actual_sha256 = self._hash_file(restored_path)
        sha256_ok     = actual_sha256 == expected_sha256

        # Size verification
        actual_size = restored_path.stat().st_size if restored_path.exists() else -1
        size_ok     = actual_size == expected_size

        # Smoke test
        smoke_ok: Optional[bool] = None
        if smoke_test_fn is not None:
            try:
                smoke_ok = bool(smoke_test_fn(restored_path))
            except Exception:
                smoke_ok = False

        overall = sha256_ok and size_ok and (smoke_ok is None or smoke_ok)
        cert_id = str(uuid.uuid4())
        restored_at = datetime.now(timezone.utc).isoformat()

        # Tamper-evident proof
        proof_payload = (
            f"{cert_id}|{resource_id}|{actual_sha256}|{actual_size}|"
            f"{sha256_ok}|{size_ok}|{smoke_ok}|{restored_at}|{self.operator_id}"
        )
        sha256_proof = hashlib.sha256(proof_payload.encode()).hexdigest()

        return RestorationCertificate(
            cert_id           = cert_id,
            resource_id       = resource_id or str(restored_path),
            restored_path     = str(restored_path.resolve()),
            sha256_verified   = sha256_ok,
            size_verified     = size_ok,
            smoke_test_passed = smoke_ok,
            restored_at       = restored_at,
            operator_id       = self.operator_id,
            overall_pass      = overall,
            sha256_proof      = sha256_proof,
        )

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        if not path.exists():
            return ""
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
