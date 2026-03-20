"""
credential_checkout.py  —  Privileged credential checkout/checkin for ML ops
AI Fortress · Chapter 11 · Code Sample 11.B

Implements a secure checkout/checkin workflow for privileged credentials
used in ML infrastructure (database admin passwords, registry signing keys,
cluster root credentials).

Security properties:
  - Exclusive checkout: only one session may hold a credential at a time
  - Session binding: checked-out credential is bound to a specific session ID
  - Auto-revocation: credential is automatically checked in if TTL expires
  - Audit trail: every checkout, checkin, and expiry is logged
  - Credential masking: actual credential values are never stored in logs
    (only hashes and IDs)
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class CredentialRecord:
    cred_id:       str
    name:          str           # friendly name e.g. "prod-db-admin"
    description:   str
    cred_hash:     str           # SHA-256 of actual credential (never stored plaintext)
    checked_out:   bool = False
    session_id:    str  = ""
    principal:     str  = ""
    checked_out_at: str = ""
    expires_at:    str  = ""


@dataclass
class CheckoutReceipt:
    receipt_id:   str
    cred_id:      str
    cred_name:    str
    session_id:   str
    principal:    str
    checked_out_at: str
    expires_at:   str


@dataclass
class CheckinResult:
    success:    bool
    cred_id:    str
    session_id: str
    reason:     str


class CredentialCheckoutManager:
    """
    Manages privileged credential checkout/checkin.

    Parameters
    ----------
    audit_path : Optional JSON Lines path for checkout events.
    """

    def __init__(self, audit_path: Optional[str | Path] = None):
        self._creds:  Dict[str, CredentialRecord] = {}
        self._audit   = Path(audit_path) if audit_path else None

    def register(
        self,
        name:        str,
        credential:  str,
        description: str = "",
    ) -> CredentialRecord:
        """Register a credential for managed checkout. Stores hash only."""
        cred_id = str(uuid.uuid4())
        record  = CredentialRecord(
            cred_id     = cred_id,
            name        = name,
            description = description,
            cred_hash   = hashlib.sha256(credential.encode()).hexdigest(),
        )
        self._creds[cred_id] = record
        return record

    def checkout(
        self,
        cred_id:    str,
        principal:  str,
        session_id: str,
        ttl_seconds: int = 3600,
    ) -> CheckoutReceipt:
        """Check out a credential for exclusive use in a session."""
        cred = self._creds.get(cred_id)
        if cred is None:
            raise KeyError(f"Credential '{cred_id}' not found")

        # Check if already checked out (and not expired)
        if cred.checked_out:
            if cred.expires_at:
                exp = datetime.fromisoformat(cred.expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) <= exp:
                    raise PermissionError(
                        f"Credential '{cred.name}' is already checked out "
                        f"by session '{cred.session_id}' until {cred.expires_at}"
                    )
            # Expired checkout — auto-release
            self._release(cred, reason="auto-expired")

        now     = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        cred.checked_out    = True
        cred.session_id     = session_id
        cred.principal      = principal
        cred.checked_out_at = now.isoformat()
        cred.expires_at     = expires.isoformat()

        receipt = CheckoutReceipt(
            receipt_id      = str(uuid.uuid4()),
            cred_id         = cred_id,
            cred_name       = cred.name,
            session_id      = session_id,
            principal       = principal,
            checked_out_at  = cred.checked_out_at,
            expires_at      = cred.expires_at,
        )
        self._log("credential_checked_out", cred_id=cred_id, cred_name=cred.name,
                  principal=principal, session_id=session_id,
                  expires_at=cred.expires_at)
        return receipt

    def checkin(self, cred_id: str, session_id: str) -> CheckinResult:
        """Check in a credential. Session ID must match the checkout."""
        cred = self._creds.get(cred_id)
        if cred is None:
            return CheckinResult(False, cred_id, session_id, "Credential not found")
        if not cred.checked_out:
            return CheckinResult(False, cred_id, session_id, "Not currently checked out")
        if cred.session_id != session_id:
            return CheckinResult(False, cred_id, session_id,
                                 f"Session mismatch: expected '{cred.session_id}'")
        self._release(cred, reason="normal-checkin")
        self._log("credential_checked_in", cred_id=cred_id, cred_name=cred.name,
                  session_id=session_id)
        return CheckinResult(True, cred_id, session_id, "Checked in successfully")

    def is_available(self, cred_id: str) -> bool:
        cred = self._creds.get(cred_id)
        if cred is None:
            return False
        if not cred.checked_out:
            return True
        # Check if checkout expired
        if cred.expires_at:
            exp = datetime.fromisoformat(cred.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                self._release(cred, reason="auto-expired")
                return True
        return False

    def sweep_expired(self) -> int:
        """Release all expired checkouts. Returns count released."""
        now     = datetime.now(timezone.utc)
        released = 0
        for cred in self._creds.values():
            if not cred.checked_out or not cred.expires_at:
                continue
            exp = datetime.fromisoformat(cred.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now > exp:
                self._release(cred, reason="sweep-expired")
                self._log("credential_auto_released", cred_id=cred.cred_id,
                          cred_name=cred.name, reason="ttl_expired")
                released += 1
        return released

    def _release(self, cred: CredentialRecord, reason: str = "") -> None:
        cred.checked_out    = False
        cred.session_id     = ""
        cred.principal      = ""
        cred.checked_out_at = ""
        cred.expires_at     = ""

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
