"""
device_identity_issuer.py  —  Device identity credential issuer
AI Fortress · Chapter 15 · Code Sample 15.D

Issues device identity certificates during factory provisioning.
Each device receives:
  - A unique Device ID (UUID v4)
  - An HMAC-SHA256 signed identity certificate containing device class,
    serial number, provisioning timestamp, and public key hash
  - A short-lived provisioning token for first-boot onboarding

In production replace HMAC with X.509 certificate issuance via a
hardware HSM-backed PKI CA.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional


@dataclass
class DeviceIdentityCert:
    device_id:       str
    serial_number:   str
    device_class:    str
    public_key_hash: str     # SHA-256 of device public key bytes
    issued_at:       str
    issuer:          str
    cert_id:         str
    signature:       str     # hex HMAC-SHA256


@dataclass
class ProvisioningToken:
    token:           str     # hex random token
    device_id:       str
    expires_at:      str
    used:            bool = False


class DeviceIdentityIssuer:
    """Issues device identity credentials during factory provisioning."""

    def __init__(self, ca_key: bytes, issuer: str = "ai-fortress-ca"):
        if len(ca_key) < 32:
            raise ValueError("ca_key must be ≥ 32 bytes")
        self._key    = ca_key
        self._issuer = issuer
        self._issued: Dict[str, DeviceIdentityCert] = {}

    def issue(
        self,
        serial_number:   str,
        device_class:    str,
        public_key_bytes: bytes,
    ) -> DeviceIdentityCert:
        device_id   = str(uuid.uuid4())
        pk_hash     = hashlib.sha256(public_key_bytes).hexdigest()
        cert_id     = str(uuid.uuid4())
        issued_at   = datetime.now(timezone.utc).isoformat()

        payload = json.dumps({
            "device_id": device_id, "serial_number": serial_number,
            "device_class": device_class, "public_key_hash": pk_hash,
            "issued_at": issued_at, "issuer": self._issuer, "cert_id": cert_id,
        }, sort_keys=True).encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).hexdigest()

        cert = DeviceIdentityCert(
            device_id=device_id, serial_number=serial_number,
            device_class=device_class, public_key_hash=pk_hash,
            issued_at=issued_at, issuer=self._issuer,
            cert_id=cert_id, signature=sig,
        )
        self._issued[device_id] = cert
        return cert

    def verify_cert(self, cert: DeviceIdentityCert) -> bool:
        import dataclasses
        d = dataclasses.asdict(cert)
        sig = d.pop("signature")
        payload = json.dumps(d, sort_keys=True).encode()
        expected = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)

    def issue_provisioning_token(self, device_id: str) -> ProvisioningToken:
        from datetime import timedelta
        token    = os.urandom(32).hex()
        exp      = datetime.now(timezone.utc).isoformat()
        return ProvisioningToken(token=token, device_id=device_id, expires_at=exp)

    def issued_count(self) -> int:
        return len(self._issued)
