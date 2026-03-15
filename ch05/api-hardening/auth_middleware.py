"""
auth_middleware.py  —  API key authentication, scopes, and audit logging
AI Fortress · Chapter 5 · Code Sample 5.A

Provides:
  - HMAC-SHA256 API key validation (keys are stored as salted hashes)
  - Per-key scope enforcement (e.g. "inference:read", "batch:write")
  - Key rotation: old key remains valid for a grace period after rotation
  - Structured auth audit events (success, failure, scope violation, rotation)
  - Constant-time comparison to prevent timing-based key enumeration

Storage: in-memory dict (dev/test). Replace with Redis or DynamoDB for prod.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set


@dataclass
class APIKey:
    key_id:       str
    key_hash:     str           # HMAC-SHA256(key, salt) — never store raw key
    salt:         str
    scopes:       Set[str]
    tier:         str           # "free" | "pro" | "enterprise"
    created_at:   str
    expires_at:   str  = ""    # "" = no expiry
    rotated_to:   str  = ""    # key_id of the replacement key
    grace_until:  str  = ""    # old key valid until this timestamp after rotation
    description:  str  = ""


class AuthenticationError(Exception):
    pass


class ScopeError(Exception):
    pass


class AuthMiddleware:
    """
    API key authentication middleware.

    Parameters
    ----------
    signing_secret : Server-side secret for HMAC (store in Secrets Manager)
    grace_seconds  : How long a rotated key remains valid (default 3600 = 1h)
    """

    def __init__(self, signing_secret: bytes, grace_seconds: int = 3600):
        self.signing_secret = signing_secret
        self.grace_seconds  = grace_seconds
        self._keys:   Dict[str, APIKey] = {}    # key_id → APIKey
        self._audit:  List[dict] = []

    def issue_key(
        self,
        scopes:      Set[str],
        tier:        str = "free",
        description: str = "",
        expires_at:  str = "",
    ) -> str:
        """
        Generate and register a new API key.
        Returns the raw key string (show to user ONCE; not stored).
        """
        raw_key = "aif_" + secrets.token_urlsafe(32)
        salt    = secrets.token_hex(16)
        key_hash = self._hash_key(raw_key, salt)
        key_id   = "kid_" + uuid.uuid4().hex[:16]

        self._keys[key_id] = APIKey(
            key_id      = key_id,
            key_hash    = key_hash,
            salt        = salt,
            scopes      = set(scopes),
            tier        = tier,
            created_at  = datetime.now(timezone.utc).isoformat(),
            expires_at  = expires_at,
            description = description,
        )
        return raw_key   # raw key returned exactly once

    def authenticate(self, raw_key: str, required_scopes: Optional[Set[str]] = None) -> APIKey:
        """
        Validate a raw API key and check scopes.
        Raises AuthenticationError or ScopeError on failure.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Find matching key by constant-time HMAC comparison
        matched_key: Optional[APIKey] = None
        for api_key in self._keys.values():
            expected = self._hash_key(raw_key, api_key.salt)
            if hmac.compare_digest(expected, api_key.key_hash):
                matched_key = api_key
                break

        if matched_key is None:
            self._audit_event("auth_failure", None, "invalid_key", now)
            raise AuthenticationError("Invalid API key")

        # Expiry check
        if matched_key.expires_at and now > matched_key.expires_at:
            self._audit_event("auth_failure", matched_key.key_id, "key_expired", now)
            raise AuthenticationError("API key has expired")

        # Rotation grace period
        if matched_key.rotated_to:
            if not matched_key.grace_until or now > matched_key.grace_until:
                self._audit_event("auth_failure", matched_key.key_id, "key_rotated", now)
                raise AuthenticationError(
                    "This API key has been rotated. Please use the new key."
                )

        # Scope check
        if required_scopes:
            missing = required_scopes - matched_key.scopes
            if missing:
                self._audit_event("scope_violation", matched_key.key_id,
                                  f"missing_scopes:{sorted(missing)}", now)
                raise ScopeError(
                    f"Key '{matched_key.key_id}' lacks required scopes: {sorted(missing)}"
                )

        self._audit_event("auth_success", matched_key.key_id, "ok", now)
        return matched_key

    def rotate_key(self, old_key_id: str, scopes: Optional[Set[str]] = None) -> str:
        """Rotate a key: issue a new one, mark old one with grace period."""
        from datetime import timedelta
        old = self._keys.get(old_key_id)
        if not old:
            raise KeyError(f"Key '{old_key_id}' not found")

        new_scopes = scopes or old.scopes
        new_raw    = self.issue_key(scopes=new_scopes, tier=old.tier,
                                     description=f"Rotated from {old_key_id}")
        # Find new key_id
        new_id = next(
            kid for kid, k in self._keys.items()
            if kid != old_key_id and k.description == f"Rotated from {old_key_id}"
        )
        grace_until = datetime.now(timezone.utc).isoformat()
        # Store grace period as ISO string offset
        from datetime import timedelta
        grace_dt = datetime.fromisoformat(grace_until) + timedelta(seconds=self.grace_seconds)
        old.rotated_to  = new_id
        old.grace_until = grace_dt.isoformat()

        self._audit_event("key_rotation", old_key_id, f"rotated_to:{new_id}",
                          datetime.now(timezone.utc).isoformat())
        return new_raw

    def audit_log(self) -> List[dict]:
        return list(self._audit)

    def _hash_key(self, raw_key: str, salt: str) -> str:
        return hmac.new(
            self.signing_secret,
            (salt + raw_key).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _audit_event(self, event_type: str, key_id: Optional[str],
                     detail: str, timestamp: str) -> None:
        self._audit.append({
            "event_id":   uuid.uuid4().hex,
            "timestamp":  timestamp,
            "event_type": event_type,
            "key_id":     key_id,
            "detail":     detail,
        })
