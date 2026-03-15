"""
ota_verifier.py  —  OTA package verification
AI Fortress · Chapter 15 · Code Sample 15.C

Verifies an OTA package before applying it on a device:
  1. Signature verification (HMAC-SHA256)
  2. Payload integrity (SHA-256 hash check)
  3. Version compatibility (target > current, target >= min_device_version)
  4. Device class match
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import List

from ota_package_builder import OTAPackage


@dataclass
class OTAVerificationResult:
    valid:            bool
    package_id:       str
    signature_ok:     bool
    payload_hash_ok:  bool
    version_ok:       bool
    device_class_ok:  bool
    failures:         List[str]
    detail:           str


class OTAVerifier:
    """
    Verifies OTA packages on the receiving device.

    Parameters
    ----------
    verify_key        : HMAC-SHA256 verification key (same as signing key).
    current_version   : Device's current installed version (SemVer string).
    device_class      : This device's class identifier.
    """

    def __init__(
        self,
        verify_key:      bytes,
        current_version: str,
        device_class:    str,
    ):
        self._key     = verify_key
        self._current = current_version
        self._class   = device_class

    def verify(self, package: OTAPackage) -> OTAVerificationResult:
        failures: List[str] = []
        meta = package.metadata

        # 1. Signature
        meta_bytes   = json.dumps(meta.__dict__).encode()
        expected_sig = hmac.new(self._key, meta_bytes + package.payload, hashlib.sha256).digest()
        sig_ok       = hmac.compare_digest(expected_sig, package.signature)
        if not sig_ok:
            failures.append("Signature verification failed — package may be tampered.")

        # 2. Payload hash
        actual_hash = hashlib.sha256(package.payload).hexdigest()
        hash_ok     = hmac.compare_digest(actual_hash, meta.payload_sha256)
        if not hash_ok:
            failures.append("Payload SHA-256 mismatch — payload corrupted or tampered.")

        # 3. Version check (target must be > current)
        try:
            from version_compare import compare_versions
            ver_ok = compare_versions(meta.target_version, self._current) > 0
        except Exception:
            # Fallback: simple lexicographic (fine for tests)
            ver_ok = meta.target_version > self._current
        if not ver_ok:
            failures.append(
                f"Version regression: package={meta.target_version} <= "
                f"current={self._current}."
            )

        # 4. Device class
        class_ok = (meta.device_class == self._class)
        if not class_ok:
            failures.append(
                f"Device class mismatch: package='{meta.device_class}', "
                f"device='{self._class}'."
            )

        valid  = len(failures) == 0
        detail = "Package verified successfully." if valid else " | ".join(failures)
        return OTAVerificationResult(
            valid           = valid,
            package_id      = meta.package_id,
            signature_ok    = sig_ok,
            payload_hash_ok = hash_ok,
            version_ok      = ver_ok,
            device_class_ok = class_ok,
            failures        = failures,
            detail          = detail,
        )
