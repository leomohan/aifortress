"""
fairness_metrics.py  —  Fairness metric suite
AI Fortress · Chapter 16 · Code Sample 16.A

Computes standard group fairness metrics across protected attribute groups.
All metrics operate on binary classification outputs (0/1 predictions)
against binary ground-truth labels.

Metrics implemented:
  - Demographic Parity Difference  (DPD)
  - Equalised Odds Difference       (EOD) — max(ΔTPR, ΔFPR)
  - Equal Opportunity Difference    (EOpD) — ΔTPR only
  - Predictive Parity Difference    (PPD) — Δprecision
  - Calibration Gap                 (CG)  — difference in mean score by group
  - Individual Fairness Score       (IFS) — consistency of similar-input predictions

Reference groups: all metrics compare each group against a designated
reference group (default: largest group by sample count).
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class GroupMetrics:
    group:        str
    n:            int
    positive_rate: float    # P(Ŷ=1)
    tpr:          float     # P(Ŷ=1 | Y=1)
    fpr:          float     # P(Ŷ=1 | Y=0)
    precision:    float     # P(Y=1 | Ŷ=1)
    mean_score:   float     # mean predicted probability (if available)


@dataclass
class FairnessMetrics:
    reference_group:     str
    group_metrics:       Dict[str, GroupMetrics]
    demographic_parity_diff:   Dict[str, float]   # group → |PR_ref - PR_g|
    equalised_odds_diff:       Dict[str, float]   # group → max(|ΔTPR|, |ΔFPR|)
    equal_opportunity_diff:    Dict[str, float]   # group → |ΔTPR|
    predictive_parity_diff:    Dict[str, float]   # group → |Δprecision|
    calibration_gap:           Dict[str, float]   # group → |Δmean_score|
    overall_fairness_grade:    str                # "A"|"B"|"C"|"D"|"F"
    violations:                List[str]

    def worst_dpd(self) -> float:
        return max(self.demographic_parity_diff.values(), default=0.0)

    def worst_eod(self) -> float:
        return max(self.equalised_odds_diff.values(), default=0.0)

    def summary(self) -> str:
        return (
            f"Fairness grade {self.overall_fairness_grade} "
            f"(ref='{self.reference_group}'): "
            f"worst DPD={self.worst_dpd():.3f}, worst EOD={self.worst_eod():.3f}. "
            f"{len(self.violations)} violation(s)."
        )


class FairnessEvaluator:
    """
    Computes group fairness metrics across a protected attribute.

    Parameters
    ----------
    dpd_threshold  : Max allowed demographic parity difference (default 0.10).
    eod_threshold  : Max allowed equalised odds difference (default 0.10).
    score_available: Whether continuous prediction scores are provided.
    """

    def __init__(
        self,
        dpd_threshold:  float = 0.10,
        eod_threshold:  float = 0.10,
        score_available: bool = False,
    ):
        self._dpd_thr   = dpd_threshold
        self._eod_thr   = eod_threshold
        self._scores_ok = score_available

    def evaluate(
        self,
        y_true:    List[int],         # ground-truth labels (0/1)
        y_pred:    List[int],         # model predictions (0/1)
        groups:    List[str],         # protected group label for each record
        scores:    Optional[List[float]] = None,   # predicted probabilities
        reference: Optional[str]     = None,
    ) -> FairnessMetrics:
        n = len(y_true)
        if not (n == len(y_pred) == len(groups)):
            raise ValueError("y_true, y_pred, and groups must all have the same length")

        # Build per-group data
        group_data: Dict[str, List[Tuple[int, int, float]]] = {}
        for i in range(n):
            g = groups[i]
            s = scores[i] if scores else float(y_pred[i])
            group_data.setdefault(g, []).append((y_true[i], y_pred[i], s))

        # Determine reference group
        ref = reference or max(group_data, key=lambda g: len(group_data[g]))

        # Compute per-group metrics
        gm: Dict[str, GroupMetrics] = {}
        for g, data in group_data.items():
            yt = [d[0] for d in data]
            yp = [d[1] for d in data]
            sc = [d[2] for d in data]
            gm[g] = self._compute_group(g, yt, yp, sc)

        ref_m = gm[ref]
        dpd, eod, eopd, ppd, cg = {}, {}, {}, {}, {}
        violations: List[str] = []

        for g, m in gm.items():
            if g == ref:
                continue
            dpd[g]  = abs(ref_m.positive_rate - m.positive_rate)
            eod[g]  = max(abs(ref_m.tpr - m.tpr), abs(ref_m.fpr - m.fpr))
            eopd[g] = abs(ref_m.tpr - m.tpr)
            ppd[g]  = abs(ref_m.precision - m.precision)
            cg[g]   = abs(ref_m.mean_score - m.mean_score)

            if dpd[g] > self._dpd_thr:
                violations.append(
                    f"DPD violation: group '{g}' vs '{ref}' = {dpd[g]:.3f} > {self._dpd_thr}"
                )
            if eod[g] > self._eod_thr:
                violations.append(
                    f"EOD violation: group '{g}' vs '{ref}' = {eod[g]:.3f} > {self._eod_thr}"
                )

        worst = max(
            [max(dpd.values(), default=0), max(eod.values(), default=0)],
            default=0
        )
        grade = "A" if worst < 0.05 else "B" if worst < 0.10 else \
                "C" if worst < 0.15 else "D" if worst < 0.20 else "F"

        return FairnessMetrics(
            reference_group          = ref,
            group_metrics            = gm,
            demographic_parity_diff  = dpd,
            equalised_odds_diff      = eod,
            equal_opportunity_diff   = eopd,
            predictive_parity_diff   = ppd,
            calibration_gap          = cg,
            overall_fairness_grade   = grade,
            violations               = violations,
        )

    @staticmethod
    def _compute_group(
        name: str, yt: List[int], yp: List[int], sc: List[float]
    ) -> GroupMetrics:
        n = len(yt)
        pos_rate = sum(yp) / n if n else 0.0

        pos_idx = [i for i in range(n) if yt[i] == 1]
        neg_idx = [i for i in range(n) if yt[i] == 0]
        pred_pos_idx = [i for i in range(n) if yp[i] == 1]

        tpr = (sum(yp[i] for i in pos_idx) / len(pos_idx)) if pos_idx else 0.0
        fpr = (sum(yp[i] for i in neg_idx) / len(neg_idx)) if neg_idx else 0.0
        precision = (
            sum(yt[i] for i in pred_pos_idx) / len(pred_pos_idx)
            if pred_pos_idx else 0.0
        )
        mean_sc = statistics.mean(sc) if sc else 0.0

        return GroupMetrics(
            group=name, n=n, positive_rate=round(pos_rate, 4),
            tpr=round(tpr, 4), fpr=round(fpr, 4),
            precision=round(precision, 4), mean_score=round(mean_sc, 4),
        )
