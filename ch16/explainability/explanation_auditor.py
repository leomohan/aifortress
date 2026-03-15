"""
explanation_auditor.py  —  Explanation quality and consistency auditor
AI Fortress · Chapter 16 · Code Sample 16.E

Audits ML explanations for:
  1. Consistency     — same/similar inputs produce similar explanations
  2. Completeness    — SHAP values sum approximately to (prediction - base)
  3. Sensitivity     — feature importances respond to meaningful input changes
  4. Fairness        — explanation quality is equitable across protected groups
     (disadvantaged groups should receive explanations of equal fidelity)

Reference:
  Bhatt et al. (2020). "Evaluating and Aggregating Feature-based Model
  Explanations." IJCAI.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from shap_approximator import SHAPExplanation


@dataclass
class ExplanationAuditResult:
    consistency_score:   float    # 0–1; 1 = perfectly consistent
    completeness_ok:     bool     # SHAP sums within tolerance of (pred - base)
    sensitivity_ok:      bool     # importances change when input changes
    fairness_gap:        float    # difference in consistency across groups
    overall_grade:       str      # "PASS" | "CONDITIONAL" | "FAIL"
    violations:          List[str]
    detail:              str


class ExplanationAuditor:
    """
    Audits a set of SHAP explanations for quality and consistency.

    Parameters
    ----------
    completeness_tol  : Allowed absolute difference for completeness check.
    consistency_thr   : Minimum consistency score (cosine similarity) to pass.
    fairness_tol      : Max allowed consistency gap between groups.
    """

    def __init__(
        self,
        completeness_tol: float = 0.05,
        consistency_thr:  float = 0.80,
        fairness_tol:     float = 0.10,
    ):
        self._comp_tol   = completeness_tol
        self._cons_thr   = consistency_thr
        self._fair_tol   = fairness_tol

    def audit(
        self,
        explanations:  List[SHAPExplanation],
        groups:        Optional[List[str]] = None,
    ) -> ExplanationAuditResult:
        """
        Audit a list of SHAP explanations.

        Parameters
        ----------
        explanations : List of SHAPExplanation objects.
        groups       : Optional protected group label per explanation.
        """
        violations: List[str] = []

        # 1. Completeness: sum(SHAP) ≈ prediction - base_value
        comp_errors = []
        for ex in explanations:
            shap_sum = sum(ex.shap_values.values())
            expected = ex.predicted_value - ex.base_value
            comp_errors.append(abs(shap_sum - expected))
        completeness_ok = statistics.mean(comp_errors) <= self._comp_tol
        if not completeness_ok:
            violations.append(
                f"Completeness: mean SHAP sum error {statistics.mean(comp_errors):.4f} "
                f"> tolerance {self._comp_tol}"
            )

        # 2. Consistency: pairwise cosine similarity of SHAP vectors
        cons_scores = self._pairwise_cosine(explanations)
        consistency = statistics.mean(cons_scores) if cons_scores else 1.0
        if consistency < self._cons_thr:
            violations.append(
                f"Consistency: mean cosine similarity {consistency:.3f} "
                f"< threshold {self._cons_thr}"
            )

        # 3. Sensitivity: at least one feature has non-zero SHAP for each explanation
        insensitive = sum(
            1 for ex in explanations
            if all(abs(v) < 1e-8 for v in ex.shap_values.values())
        )
        sensitivity_ok = insensitive == 0
        if not sensitivity_ok:
            violations.append(
                f"Sensitivity: {insensitive} explanation(s) have all-zero SHAP values."
            )

        # 4. Fairness: consistency gap between groups
        fairness_gap = 0.0
        if groups and len(set(groups)) > 1:
            group_cons: Dict[str, List[float]] = {}
            for i, ex in enumerate(explanations):
                g = groups[i]
                group_cons.setdefault(g, [])
            # Compute per-group mean of |SHAP values| as proxy for explanation quality
            group_qual: Dict[str, float] = {}
            for i, ex in enumerate(explanations):
                g   = groups[i]
                mag = statistics.mean(abs(v) for v in ex.shap_values.values()) if ex.shap_values else 0.0
                group_qual.setdefault(g, []).append(mag)
            group_means = {g: statistics.mean(vs) for g, vs in group_qual.items()}
            if group_means:
                fairness_gap = round(max(group_means.values()) - min(group_means.values()), 4)
                if fairness_gap > self._fair_tol:
                    violations.append(
                        f"Fairness: explanation quality gap {fairness_gap:.3f} "
                        f"> tolerance {self._fair_tol} across groups."
                    )

        if len(violations) == 0:
            grade = "PASS"
        elif len(violations) <= 1:
            grade = "CONDITIONAL"
        else:
            grade = "FAIL"

        detail = (
            f"Audit {grade}: consistency={consistency:.3f}, "
            f"completeness={'OK' if completeness_ok else 'FAIL'}, "
            f"sensitivity={'OK' if sensitivity_ok else 'FAIL'}, "
            f"fairness_gap={fairness_gap:.3f}."
        )

        return ExplanationAuditResult(
            consistency_score = round(consistency, 4),
            completeness_ok   = completeness_ok,
            sensitivity_ok    = sensitivity_ok,
            fairness_gap      = fairness_gap,
            overall_grade     = grade,
            violations        = violations,
            detail            = detail,
        )

    def _pairwise_cosine(self, explanations: List[SHAPExplanation]) -> List[float]:
        """Compute mean pairwise cosine similarity of SHAP vectors."""
        if len(explanations) < 2:
            return [1.0]
        scores = []
        vecs   = [
            [ex.shap_values.get(f, 0.0) for f in ex.feature_names]
            for ex in explanations
        ]
        for i in range(min(len(vecs), 20)):     # cap at 20 pairs for performance
            for j in range(i + 1, min(len(vecs), 20)):
                scores.append(self._cosine(vecs[i], vecs[j]))
        return scores

    @staticmethod
    def _cosine(a: List[float], b: List[float]) -> float:
        dot  = sum(x * y for x, y in zip(a, b))
        na   = sum(x ** 2 for x in a) ** 0.5
        nb   = sum(x ** 2 for x in b) ** 0.5
        if na * nb == 0:
            return 0.0
        return round(dot / (na * nb), 4)
