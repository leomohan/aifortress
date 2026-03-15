"""
platform_integrity_checker.py  —  Platform integrity PCR baseline checker
AI Fortress · Chapter 15 · Code Sample 15.A

Compares current PCR values from an attestation quote against a
stored golden measurement baseline. Produces a per-PCR pass/fail
report and an overall integrity verdict.

Golden measurements should be established in a known-good provisioning
environment and stored in an append-only, access-controlled registry.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class PCRCheckResult:
    pcr_index:  int
    expected:   str
    actual:     str
    match:      bool
    masked:     bool    # True if this PCR is excluded from evaluation


@dataclass
class PlatformIntegrityReport:
    device_id:      str
    verdict:        str      # "PASS" | "FAIL" | "PARTIAL"
    checked_at:     str
    pcr_results:    List[PCRCheckResult]
    failed_pcrs:    List[int]
    masked_pcrs:    List[int]
    baseline_id:    str
    detail:         str

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


@dataclass
class GoldenBaseline:
    baseline_id:  str
    device_class: str
    pcr_values:   Dict[int, str]   # PCR index → expected SHA-256 hex
    created_at:   str
    description:  str = ""


class PlatformIntegrityChecker:
    """
    Checks current platform PCR values against a golden measurement baseline.

    Parameters
    ----------
    pcr_mask : Set of PCR indices to INCLUDE in evaluation.
               PCRs not in the mask are skipped (e.g. PCR[1] varies per config).
               If None, all PCRs present in the baseline are checked.
    """

    _DEFAULT_MASK = {0, 2, 4, 7, 8, 9}   # firmware, boot loader, secure boot, kernel

    def __init__(self, pcr_mask: Optional[Set[int]] = None):
        self._mask = pcr_mask if pcr_mask is not None else self._DEFAULT_MASK

    def check(
        self,
        device_id:   str,
        current_pcrs: Dict[int, str],
        baseline:    GoldenBaseline,
    ) -> PlatformIntegrityReport:
        """
        Compare current PCR values against the golden baseline.

        Parameters
        ----------
        device_id    : Device being checked.
        current_pcrs : Dict of PCR index → current SHA-256 hex from attestation quote.
        baseline     : GoldenBaseline for this device class.
        """
        results: List[PCRCheckResult] = []
        failed:  List[int]            = []
        masked:  List[int]            = []

        for pcr_idx, expected in baseline.pcr_values.items():
            is_masked = pcr_idx not in self._mask
            actual    = current_pcrs.get(pcr_idx, "")
            match     = (actual == expected) if not is_masked else True

            results.append(PCRCheckResult(
                pcr_index = pcr_idx,
                expected  = expected,
                actual    = actual,
                match     = match,
                masked    = is_masked,
            ))
            if is_masked:
                masked.append(pcr_idx)
            elif not match:
                failed.append(pcr_idx)

        if not failed:
            verdict = "PASS"
            detail  = f"All {len(self._mask)} evaluated PCRs match baseline '{baseline.baseline_id}'."
        else:
            verdict = "FAIL"
            detail  = (
                f"PCR mismatch on indices {failed}. "
                f"Possible firmware/boot modification on device '{device_id}'."
            )

        return PlatformIntegrityReport(
            device_id   = device_id,
            verdict     = verdict,
            checked_at  = datetime.now(timezone.utc).isoformat(),
            pcr_results = results,
            failed_pcrs = failed,
            masked_pcrs = masked,
            baseline_id = baseline.baseline_id,
            detail      = detail,
        )

    def register_baseline(
        self,
        baseline_id:  str,
        device_class: str,
        pcr_values:   Dict[int, str],
        description:  str = "",
    ) -> GoldenBaseline:
        return GoldenBaseline(
            baseline_id  = baseline_id,
            device_class = device_class,
            pcr_values   = dict(pcr_values),
            created_at   = datetime.now(timezone.utc).isoformat(),
            description  = description,
        )
