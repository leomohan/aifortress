"""
membership_inference.py  —  Membership inference attack baseline
AI Fortress · Chapter 13 · Code Sample 13.D

Implements a confidence-thresholding membership inference attack.
The attacker observes model prediction confidence for a set of
known members (training records) and non-members (held-out records),
and thresholds confidence to predict membership.

A well-protected model should produce attack AUC ≈ 0.5 (random guessing).
AUC > 0.7 indicates significant membership leakage.

Reference: Shokri et al., "Membership Inference Attacks Against Machine
Learning Models" (IEEE S&P 2017).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class MIAResult:
    attack_auc:         float    # ROC AUC of membership prediction
    best_threshold:     float    # confidence threshold maximising TPR - FPR
    tpr_at_threshold:   float    # true positive rate (member correctly classified)
    fpr_at_threshold:   float    # false positive rate (non-member misclassified)
    advantage:          float    # TPR - FPR (should be ≈ 0 for private model)
    severity:           str      # "critical" | "high" | "moderate" | "low"
    n_members:          int
    n_non_members:      int

    def summary(self) -> str:
        return (
            f"MIA AUC={self.attack_auc:.3f}, advantage={self.advantage:.3f} "
            f"({self.severity}). "
            f"Threshold={self.best_threshold:.3f}: "
            f"TPR={self.tpr_at_threshold:.3f}, FPR={self.fpr_at_threshold:.3f}."
        )


def _auc_from_scores(
    member_confs: List[float],
    nonmember_confs: List[float],
) -> float:
    """Compute AUC via Mann-Whitney U statistic."""
    n_m  = len(member_confs)
    n_nm = len(nonmember_confs)
    if n_m == 0 or n_nm == 0:
        return 0.5
    u = sum(
        1.0 if m > nm else 0.5 if m == nm else 0.0
        for m in member_confs for nm in nonmember_confs
    )
    return u / (n_m * n_nm)


class MembershipInferenceAuditor:
    """
    Confidence-thresholding membership inference attack.

    Parameters
    ----------
    n_thresholds : Number of threshold candidates to sweep.
    """

    def __init__(self, n_thresholds: int = 100):
        self._n_thresh = n_thresholds

    def audit(
        self,
        member_confidences:     List[float],   # model confidence on training records
        nonmember_confidences:  List[float],   # model confidence on held-out records
    ) -> MIAResult:
        """
        Run membership inference audit.

        Parameters
        ----------
        member_confidences    : Max prediction confidence for each training record.
        nonmember_confidences : Max prediction confidence for each held-out record.
        """
        auc = _auc_from_scores(member_confidences, nonmember_confidences)

        # Sweep thresholds to find best advantage
        all_confs = member_confidences + nonmember_confidences
        lo, hi    = min(all_confs), max(all_confs)
        step      = (hi - lo) / self._n_thresh if hi > lo else 0.01

        best_adv, best_t, best_tpr, best_fpr = 0.0, 0.5, 0.5, 0.5
        for i in range(self._n_thresh + 1):
            t    = lo + i * step
            tpr  = sum(1 for c in member_confidences    if c >= t) / max(len(member_confidences), 1)
            fpr  = sum(1 for c in nonmember_confidences if c >= t) / max(len(nonmember_confidences), 1)
            adv  = tpr - fpr
            if adv > best_adv:
                best_adv, best_t, best_tpr, best_fpr = adv, t, tpr, fpr

        severity = (
            "critical" if auc > 0.80 else
            "high"     if auc > 0.70 else
            "moderate" if auc > 0.60 else
            "low"
        )
        return MIAResult(
            attack_auc        = round(auc, 4),
            best_threshold    = round(best_t, 4),
            tpr_at_threshold  = round(best_tpr, 4),
            fpr_at_threshold  = round(best_fpr, 4),
            advantage         = round(best_adv, 4),
            severity          = severity,
            n_members         = len(member_confidences),
            n_non_members     = len(nonmember_confidences),
        )
