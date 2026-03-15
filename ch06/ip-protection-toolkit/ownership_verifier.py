"""
ownership_verifier.py  —  Black-box API ownership verification
AI Fortress · Chapter 6 · Code Sample 6.C

Combines model fingerprinting + weight watermark verification into a single
ownership verification report suitable for legal/regulatory proceedings.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import numpy as np

from model_fingerprinter import ModelFingerprinter, ModelFingerprint, FingerprintMatchResult


@dataclass
class OwnershipReport:
    report_id:         str
    owner_id:          str
    model_name:        str
    generated_at:      str
    fingerprint_match: bool
    fingerprint_agreement: float
    fingerprint_p_value:   float
    weight_watermark_detected: Optional[bool]
    weight_watermark_ber:      Optional[float]
    overall_verdict:   str        # "OWNER_CONFIRMED" | "INCONCLUSIVE" | "NOT_OWNER"
    confidence:        str        # "HIGH" | "MEDIUM" | "LOW"
    evidence_summary:  str

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__), indent=2)


class OwnershipVerifier:
    """
    Performs black-box ownership verification against a suspect model API.

    Parameters
    ----------
    owner_id     : Claimed model owner
    fingerprint  : Owner's ModelFingerprint
    """

    def __init__(self, owner_id: str, fingerprint: ModelFingerprint):
        self.owner_id    = owner_id
        self.fingerprint = fingerprint
        self._fp_checker = ModelFingerprinter(owner_id)

    def verify(
        self,
        suspect_fn:          Callable[[np.ndarray], np.ndarray],
        model_name:          str = "",
        weight_watermark_result=None,   # optional WeightWatermarker verify result
    ) -> OwnershipReport:
        """Run ownership verification against `suspect_fn`."""
        fp_result: FingerprintMatchResult = self._fp_checker.match(
            self.fingerprint, suspect_fn
        )

        wm_detected = None
        wm_ber      = None
        if weight_watermark_result is not None:
            wm_detected = weight_watermark_result.detected
            wm_ber      = weight_watermark_result.bit_error_rate

        # Verdict logic
        if fp_result.match and (wm_detected is True or wm_detected is None):
            verdict    = "OWNER_CONFIRMED"
            confidence = "HIGH" if fp_result.agreement_rate >= 0.90 else "MEDIUM"
        elif fp_result.match:
            verdict    = "OWNER_CONFIRMED"
            confidence = "MEDIUM"
        elif fp_result.agreement_rate >= 0.60:
            verdict    = "INCONCLUSIVE"
            confidence = "LOW"
        else:
            verdict    = "NOT_OWNER"
            confidence = "HIGH"

        evidence = (
            f"Fingerprint agreement: {fp_result.agreement_rate:.1%} "
            f"(threshold {fp_result.threshold:.0%}, p={fp_result.p_value:.4f}). "
        )
        if wm_detected is not None:
            evidence += f"Weight watermark: {'detected' if wm_detected else 'NOT detected'} "
            if wm_ber is not None:
                evidence += f"(BER={wm_ber:.3f})."

        return OwnershipReport(
            report_id                = str(uuid.uuid4()),
            owner_id                 = self.owner_id,
            model_name               = model_name or self.fingerprint.model_name,
            generated_at             = datetime.now(timezone.utc).isoformat(),
            fingerprint_match        = fp_result.match,
            fingerprint_agreement    = fp_result.agreement_rate,
            fingerprint_p_value      = fp_result.p_value,
            weight_watermark_detected = wm_detected,
            weight_watermark_ber     = wm_ber,
            overall_verdict          = verdict,
            confidence               = confidence,
            evidence_summary         = evidence,
        )
