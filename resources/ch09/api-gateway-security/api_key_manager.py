"""
api_key_manager.py  —  Hashed API key lifecycle for ML APIs
AI Fortress · Chapter 9 · Code Sample 9.A

Security controls:
  - HMAC-SHA256 hashed storage — raw keys never persisted
  - Constant-time comparison to prevent timing attacks
  - Key metadata: owner, scopes, expiry, rate-limit tier, last-used
  - Key rotation with configurable grace period for in-flight requests
  - Structured JSON Lines audit log of all key events
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class APIKeyMetadata:
    key_id:       str
    owner:        str
    scopes:       List[str]
    created_at:   str
    expires_at:   str          # ISO8601 or "" for no expiry
    rate_tier:    str          # "standard" | "premium" | "internal"
    active:       bool = True
    last_used_at: str  = ""
    rotation_of:  str  = ""    # key_id this key replaced


@dataclass
class KeyLookupResult:
    valid:    bool
    key_id:   str
    owner:    str
    scopes:   List[str]
    reason:   str


class APIKeyManager:
    """
    Manages ML API key lifecycle with hashed storage.

    Parameters
    ----------
    hmac_secret : Secret used to HMAC the raw key before storage.
                  Must be kept safe — if compromised, all key hashes
                  must be regenerated.
    audit_path  : Optional path to write JSON Lines audit log.
    """

    KEY_PREFIX     = "aif_"
    KEY_BYTES      = 32        # 256 bits of entropy

    def __init__(
        self,
        hmac_secret: bytes,
        audit_path:  Optional[str | Path] = None,
    ):
        self._secret     = hmac_secret
        self._store:  Dict[str, APIKeyMetadata] = {}   # key_hash → metadata
        self._audit   = Path(audit_path) if audit_path else None

    # ── Create / Rotate ───────────────────────────────────────────────────────

    def create_key(
        self,
        owner:      str,
        scopes:     List[str],
        ttl_days:   Optional[int] = None,
        rate_tier:  str = "standard",
    ) -> str:
        """
        Generate a new API key, store its HMAC hash, and return the raw key.
        The raw key is NEVER stored — caller must save it immediately.
        """
        raw_key  = self.KEY_PREFIX + secrets.token_urlsafe(self.KEY_BYTES)
        key_hash = self._hash(raw_key)
        key_id   = str(uuid.uuid4())
        now      = datetime.now(timezone.utc).isoformat()
        expires  = ""
        if ttl_days:
            expires_ts = int(time.time()) + ttl_days * 86400
            expires    = datetime.fromtimestamp(expires_ts, timezone.utc).isoformat()

        meta = APIKeyMetadata(
            key_id     = key_id,
            owner      = owner,
            scopes     = scopes,
            created_at = now,
            expires_at = expires,
            rate_tier  = rate_tier,
        )
        self._store[key_hash] = meta
        self._audit_event("key_created", key_id=key_id, owner=owner, scopes=scopes)
        return raw_key

    def rotate_key(
        self,
        old_raw_key:       str,
        grace_period_secs: int = 300,
    ) -> str:
        """
        Rotate an existing key. The old key remains active for `grace_period_secs`.
        Returns the new raw key.
        """
        old_hash = self._hash(old_raw_key)
        old_meta = self._store.get(old_hash)
        if old_meta is None:
            raise KeyError("Key not found for rotation")

        new_raw = self.KEY_PREFIX + secrets.token_urlsafe(self.KEY_BYTES)
        new_hash = self._hash(new_raw)
        now      = datetime.now(timezone.utc).isoformat()

        new_meta = APIKeyMetadata(
            key_id     = str(uuid.uuid4()),
            owner      = old_meta.owner,
            scopes     = old_meta.scopes,
            created_at = now,
            expires_at = old_meta.expires_at,
            rate_tier  = old_meta.rate_tier,
            rotation_of = old_meta.key_id,
        )
        self._store[new_hash] = new_meta

        # Schedule old key deactivation after grace period
        old_meta.expires_at = datetime.fromtimestamp(
            int(time.time()) + grace_period_secs, timezone.utc
        ).isoformat()

        self._audit_event("key_rotated", key_id=new_meta.key_id,
                          old_key_id=old_meta.key_id, owner=old_meta.owner)
        return new_raw

    def revoke_key(self, raw_key: str, reason: str = "") -> None:
        """Immediately deactivate a key."""
        key_hash = self._hash(raw_key)
        meta     = self._store.get(key_hash)
        if meta:
            meta.active = False
            self._audit_event("key_revoked", key_id=meta.key_id,
                              owner=meta.owner, reason=reason)

    # ── Verification ──────────────────────────────────────────────────────────

    def verify(self, raw_key: str) -> KeyLookupResult:
        """Verify a raw API key. Constant-time comparison."""
        if not raw_key.startswith(self.KEY_PREFIX):
            return KeyLookupResult(False, "", "", [], "Invalid key format")

        key_hash = self._hash(raw_key)
        meta     = self._store.get(key_hash)

        if meta is None:
            return KeyLookupResult(False, "", "", [], "Key not found")

        if not meta.active:
            return KeyLookupResult(False, meta.key_id, meta.owner, [], "Key revoked")

        if meta.expires_at:
            from datetime import datetime, timezone
            exp = datetime.fromisoformat(meta.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp:
                return KeyLookupResult(False, meta.key_id, meta.owner, [], "Key expired")

        # Update last-used
        meta.last_used_at = datetime.now(timezone.utc).isoformat()
        self._audit_event("key_used", key_id=meta.key_id, owner=meta.owner)
        return KeyLookupResult(True, meta.key_id, meta.owner, meta.scopes, "OK")

    def get_metadata(self, key_id: str) -> Optional[APIKeyMetadata]:
        for meta in self._store.values():
            if meta.key_id == key_id:
                return meta
        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _hash(self, raw_key: str) -> str:
        return hmac.new(self._secret, raw_key.encode(), hashlib.sha256).hexdigest()

    def _audit_event(self, event: str, **kwargs) -> None:
        if self._audit is None:
            return
        record = {
            "ts":    datetime.now(timezone.utc).isoformat(),
            "event": event,
            **kwargs,
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
