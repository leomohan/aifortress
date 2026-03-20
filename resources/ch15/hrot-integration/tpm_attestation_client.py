"""
tpm_attestation_client.py  —  TPM 2.0 attestation quote client
AI Fortress · Chapter 15 · Code Sample 15.A

Simulates the TPM2_Quote flow for edge AI device attestation.
In production, replace the _simulate_tpm_quote() stub with calls
to tpm2-tools CLI or the TSS2 Python bindings.

TPM2_Quote flow:
  1. Challenger sends a fresh nonce to the device
  2. Device TPM signs PCR[0..N] || nonce with its AIK private key
  3. Challenger verifies signature against the AIK certificate
  4. Challenger checks PCR values against golden baseline
  5. If all checks pass, device is considered trustworthy

PCR register allocations (TPM 2.0 typical):
  PCR[0]  — BIOS/UEFI firmware
  PCR[1]  — BIOS/UEFI configuration
  PCR[2]  — Option ROM code
  PCR[3]  — Option ROM config
  PCR[4]  — Boot loader (MBR/GPT)
  PCR[5]  — Boot loader config
  PCR[6]  — Resume from hibernate
  PCR[7]  — Secure boot state
  PCR[8..15] — OS / grub / kernel / initrd
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


_N_PCR = 24   # TPM 2.0 has 24 PCR registers


@dataclass
class AttestationQuote:
    device_id:     str
    nonce:         str          # hex nonce from challenger
    pcr_values:    Dict[int, str]   # PCR index → SHA-256 hex digest
    quote_digest:  str          # HMAC of PCR bank + nonce (simulates TPM signature)
    algorithm:     str          # "sha256"
    timestamp:     str
    aik_cert_id:   str          # ID of the AIK cert used
    quote_valid:   bool         # True after successful verification


@dataclass
class QuoteVerificationResult:
    valid:           bool
    device_id:       str
    nonce_matches:   bool
    signature_ok:    bool
    pcr_count:       int
    failures:        List[str]
    verified_at:     str


class TPMAttestationClient:
    """
    Simulates TPM 2.0 attestation quote generation and verification.

    Parameters
    ----------
    signing_key  : Secret key bytes simulating the AIK private key.
                   In production this never leaves the TPM.
    aik_cert_id  : Identifier for the AIK certificate (EK cert chain reference).
    """

    def __init__(
        self,
        signing_key: bytes,
        aik_cert_id: str = "aik-cert-v1",
    ):
        if len(signing_key) < 32:
            raise ValueError("signing_key must be ≥ 32 bytes")
        self._key       = signing_key
        self._aik_cert  = aik_cert_id

    def generate_nonce(self) -> str:
        """Generate a fresh 32-byte challenger nonce (hex)."""
        return os.urandom(32).hex()

    def quote(
        self,
        device_id:  str,
        nonce:      str,
        pcr_values: Dict[int, str],
    ) -> AttestationQuote:
        """
        Generate an attestation quote for a set of PCR values.

        Parameters
        ----------
        device_id  : Unique device identifier.
        nonce      : Challenger nonce (hex) to prevent replay.
        pcr_values : Dict of PCR index → SHA-256 hex digest.
        """
        # Canonical PCR bank representation
        pcr_bank = self._pcr_canonical(pcr_values)
        message  = f"{nonce}|{pcr_bank}".encode()
        digest   = hmac.new(self._key, message, hashlib.sha256).hexdigest()

        return AttestationQuote(
            device_id    = device_id,
            nonce        = nonce,
            pcr_values   = dict(pcr_values),
            quote_digest = digest,
            algorithm    = "sha256",
            timestamp    = datetime.now(timezone.utc).isoformat(),
            aik_cert_id  = self._aik_cert,
            quote_valid  = False,   # set to True after verification
        )

    def verify(
        self,
        quote:          AttestationQuote,
        expected_nonce: str,
    ) -> QuoteVerificationResult:
        """
        Verify a quote received from a device.

        Parameters
        ----------
        quote          : AttestationQuote from the device.
        expected_nonce : The nonce this challenger originally issued.
        """
        failures: List[str] = []
        now       = datetime.now(timezone.utc).isoformat()

        # 1. Nonce binding
        nonce_ok  = hmac.compare_digest(quote.nonce, expected_nonce)
        if not nonce_ok:
            failures.append("Nonce mismatch — possible replay attack.")

        # 2. Re-derive expected digest
        pcr_bank  = self._pcr_canonical(quote.pcr_values)
        message   = f"{quote.nonce}|{pcr_bank}".encode()
        expected  = hmac.new(self._key, message, hashlib.sha256).hexdigest()
        sig_ok    = hmac.compare_digest(expected, quote.quote_digest)
        if not sig_ok:
            failures.append("Quote signature invalid — possible tampering.")

        valid = nonce_ok and sig_ok
        if valid:
            quote.quote_valid = True

        return QuoteVerificationResult(
            valid         = valid,
            device_id     = quote.device_id,
            nonce_matches = nonce_ok,
            signature_ok  = sig_ok,
            pcr_count     = len(quote.pcr_values),
            failures      = failures,
            verified_at   = now,
        )

    @staticmethod
    def _pcr_canonical(pcr_values: Dict[int, str]) -> str:
        """Produce a canonical string representation of a PCR bank."""
        return ";".join(
            f"PCR{k:02d}={v}" for k, v in sorted(pcr_values.items())
        )

    @staticmethod
    def extend_pcr(current: str, measurement: bytes) -> str:
        """
        Simulate TPM PCRExtend: SHA-256(current_value || new_measurement).
        Initial PCR value is 32 zero bytes.
        """
        return hashlib.sha256(
            bytes.fromhex(current) + measurement
        ).hexdigest()

    @staticmethod
    def initial_pcr() -> str:
        """Return the initial PCR value (32 zero bytes)."""
        return "00" * 32
