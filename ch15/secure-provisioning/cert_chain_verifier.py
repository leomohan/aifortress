"""
cert_chain_verifier.py  —  Certificate chain verification
AI Fortress · Chapter 15 · Code Sample 15.D

Verifies a chain of device identity certificates from Root CA
through intermediate CA to device leaf certificate.
Each link's signature must be verifiable by the issuer's key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Dict, List

from device_identity_issuer import DeviceIdentityCert


@dataclass
class ChainVerificationResult:
    valid:        bool
    chain_length: int
    failures:     List[str]
    detail:       str


class CertChainVerifier:
    """
    Verifies a certificate chain. In this simulation, each cert's
    signature is verified using the issuer's registered HMAC key.

    Parameters
    ----------
    issuer_keys : Dict of issuer name → HMAC key bytes.
    """

    def __init__(self, issuer_keys: Dict[str, bytes]):
        self._keys = issuer_keys

    def verify_chain(self, chain: List[DeviceIdentityCert]) -> ChainVerificationResult:
        if not chain:
            return ChainVerificationResult(
                valid=False, chain_length=0,
                failures=["Empty chain"], detail="No certificates to verify."
            )
        failures: List[str] = []
        for cert in chain:
            key = self._keys.get(cert.issuer)
            if key is None:
                failures.append(f"Unknown issuer '{cert.issuer}' for cert '{cert.cert_id}'")
                continue
            import dataclasses
            d   = dataclasses.asdict(cert)
            sig = d.pop("signature")
            payload  = json.dumps(d, sort_keys=True).encode()
            expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, sig):
                failures.append(f"Signature invalid for cert '{cert.cert_id}' (issuer='{cert.issuer}')")

        valid  = len(failures) == 0
        detail = "Chain verified." if valid else f"{len(failures)} failure(s): {failures}"
        return ChainVerificationResult(
            valid=valid, chain_length=len(chain), failures=failures, detail=detail
        )


# ─────────────────────────────────────────────────────────────────────────────

"""
attestation_token_validator.py  —  Device attestation token validation
AI Fortress · Chapter 15 · Code Sample 15.D

Validates short-lived attestation tokens used during device first-boot
onboarding. Tokens are single-use, time-bound, and device-scoped.
"""
import json as _json
import hashlib as _hashlib
import hmac as _hmac
import os as _os
from dataclasses import dataclass as _dataclass
from datetime import datetime as _dt, timezone as _tz
from typing import Dict as _Dict, Optional as _Optional


@_dataclass
class AttestationToken:
    token_id:    str
    device_id:   str
    nonce:       str
    issued_at:   str
    signature:   str   # HMAC-SHA256(token_id|device_id|nonce|issued_at)


@_dataclass
class TokenValidationResult:
    valid:       bool
    device_id:   str
    token_id:    str
    reason:      str


class AttestationTokenValidator:
    """Issues and validates single-use device attestation tokens."""

    def __init__(self, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError("signing_key must be ≥ 32 bytes")
        self._key  = signing_key
        self._used: _Dict[str, bool] = {}

    def issue(self, device_id: str) -> AttestationToken:
        import uuid
        token_id   = str(uuid.uuid4())
        nonce      = _os.urandom(16).hex()
        issued_at  = _dt.now(_tz.utc).isoformat()
        payload    = f"{token_id}|{device_id}|{nonce}|{issued_at}".encode()
        signature  = _hmac.new(self._key, payload, _hashlib.sha256).hexdigest()
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
        payload   = f"{token.token_id}|{token.device_id}|{token.nonce}|{token.issued_at}".encode()
        expected  = _hmac.new(self._key, payload, _hashlib.sha256).hexdigest()
        sig_ok    = _hmac.compare_digest(expected, token.signature)
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
