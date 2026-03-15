"""
canary_auditor.py  —  Canary insertion privacy auditor
AI Fortress · Chapter 13 · Code Sample 13.D

Measures exposure of canary records deliberately inserted into
training data. If the model memorises canaries, their prediction
confidence will be significantly higher than non-canary records
with similar properties.

Exposure score (Carlini et al. 2019, "Secret Sharer"):
  exposure = log2(n_canaries) - log2(rank_of_canary_perplexity)

A high exposure score indicates the model has memorised the canary
and an adversary could extract it by querying the model.

Reference: Carlini et al. (2019). "The Secret Sharer: Evaluating and
Testing Unintended Memorisation in Neural Networks." USENIX Security.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class CanaryRecord:
    canary_id:  str
    confidence: float    # model confidence on this canary record
    inserted:   bool = True


@dataclass
class CanaryExposureResult:
    canary_id:       str
    confidence:      float
    rank:            int       # rank among all records (lower rank = higher conf)
    exposure_score:  float     # higher = more memorised
    severity:        str       # "critical" | "high" | "moderate" | "low"


@dataclass
class CanaryAuditReport:
    n_canaries:           int
    n_non_canaries:       int
    mean_canary_conf:     float
    mean_noncanary_conf:  float
    confidence_lift:      float   # how much higher canaries score than baseline
    max_exposure_score:   float
    mean_exposure_score:  float
    canary_results:       List[CanaryExposureResult]
    severity:             str
    recommendation:       str

    def summary(self) -> str:
        return (
            f"Canary audit: {self.n_canaries} canaries, "
            f"lift={self.confidence_lift:.4f}, "
            f"max_exposure={self.max_exposure_score:.2f} bits ({self.severity}). "
            f"{self.recommendation}"
        )


class CanaryAuditor:
    """
    Measures privacy exposure via canary confidence analysis.
    """

    def audit(
        self,
        canary_confidences:     List[float],   # confidence on canary records
        noncanary_confidences:  List[float],   # confidence on normal records
        canary_ids:             Optional[List[str]] = None,
    ) -> CanaryAuditReport:
        n_c   = len(canary_confidences)
        n_nc  = len(noncanary_confidences)
        if n_c == 0:
            raise ValueError("canary_confidences must not be empty")

        ids = canary_ids or [f"canary-{i}" for i in range(n_c)]
        all_confs = canary_confidences + noncanary_confidences
        all_sorted = sorted(all_confs, reverse=True)

        mean_c  = sum(canary_confidences) / n_c
        mean_nc = sum(noncanary_confidences) / max(n_nc, 1)
        lift    = mean_c - mean_nc

        results: List[CanaryExposureResult] = []
        for cid, conf in zip(ids, canary_confidences):
            rank     = all_sorted.index(conf) + 1
            n_total  = len(all_confs)
            # Exposure: bits of information revealed about canary membership
            exposure = max(0.0, math.log2(n_total) - math.log2(rank))
            severity = (
                "critical" if exposure > 10 else
                "high"     if exposure > 5  else
                "moderate" if exposure > 2  else
                "low"
            )
            results.append(CanaryExposureResult(
                canary_id=cid, confidence=conf,
                rank=rank, exposure_score=round(exposure, 3), severity=severity,
            ))

        max_exp  = max(r.exposure_score for r in results)
        mean_exp = sum(r.exposure_score for r in results) / n_c

        overall_sev = (
            "critical" if max_exp > 10 else
            "high"     if max_exp > 5  else
            "moderate" if max_exp > 2  else
            "low"
        )
        rec = (
            "⚠️ High memorisation detected. Apply DP training (ε < 10) or reduce "
            "training epochs." if max_exp > 5
            else "✅ Canary exposure within acceptable bounds."
        )

        return CanaryAuditReport(
            n_canaries          = n_c,
            n_non_canaries      = n_nc,
            mean_canary_conf    = round(mean_c, 4),
            mean_noncanary_conf = round(mean_nc, 4),
            confidence_lift     = round(lift, 4),
            max_exposure_score  = round(max_exp, 3),
            mean_exposure_score = round(mean_exp, 3),
            canary_results      = results,
            severity            = overall_sev,
            recommendation      = rec,
        )
