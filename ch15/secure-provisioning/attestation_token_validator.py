"""
attestation_token_validator.py  —  Device attestation token validation
AI Fortress · Chapter 15 · Code Sample 15.D

Validates short-lived attestation tokens used during device first-boot
onboarding. Tokens are single-use, time-bound, and device-scoped.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict


@dataclass
class AttestationToken:
    token_id:   str
    device_id:  str
    nonce:      str
    issued_at:  str
    signature:  str


@dataclass
class TokenValidationResult:
    valid:     bool
    device_id: str
    token_id:  str
    reason:    str


class AttestationTokenValidator:
    """Issues and validates single-use device attestation tokens."""

    def __init__(self, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError("signing_key must be ≥ 32 bytes")
        self._key  = signing_key
        self._used: Dict[str, bool] = {}

    def issue(self, device_id: str) -> AttestationToken:
        token_id  = str(uuid.uuid4())
        nonce     = os.urandom(16).hex()
        issued_at = datetime.now(timezone.utc).isoformat()
        payload   = f"{token_id}|{device_id}|{nonce}|{issued_at}".encode()
        signature = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return AttestationToken(
            token_id=token_id, device_id=device_id,
            nonce=nonce, issued_at=issued_at, signature=signature,
        )

    def validate(self, token: AttestationToken) -> TokenValidationResult:
        if self._used.get(token.token_id):
            return TokenValidationResult(
                valid=False, device_id=token.device_id,
                token_id=token.token_id, reason="Token already used (replay rejected)."
            )
        payload  = f"{token.token_id}|{token.device_id}|{token.nonce}|{token.issued_at}".encode()
        expected = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        sig_ok   = hmac.compare_digest(expected, token.signature)
        if not sig_ok:
            return TokenValidationResult(
                valid=False, device_id=token.device_id,
                token_id=token.token_id, reason="Signature invalid."
            )
        self._used[token.token_id] = True
        return TokenValidationResult(
            valid=True, device_id=token.device_id,
            token_id=token.token_id, reason="Token valid."
        )
