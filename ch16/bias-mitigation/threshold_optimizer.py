"""
threshold_optimizer.py  —  Post-processing per-group threshold optimisation
AI Fortress · Chapter 16 · Code Sample 16.B

Optimises per-group decision thresholds to equalise a target fairness
metric (demographic parity, equal opportunity, or equalised odds)
while maximising overall accuracy.

Algorithm:
  For each group, sweep thresholds in [0, 1] and find the threshold
  that minimises the discrepancy from the target rate, subject to
  maintaining accuracy above a minimum floor.

Reference:
  Hardt, Price & Srebro (2016). "Equality of Opportunity in Supervised
  Learning." NeurIPS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Tuple


@dataclass
class GroupThreshold:
    group:          str
    threshold:      float      # decision threshold for this group
    positive_rate:  float      # rate under this threshold
    tpr:            float
    accuracy:       float


@dataclass
class ThresholdOptimisationResult:
    target_metric:      str
    thresholds:         Dict[str, float]     # group → threshold
    group_results:      Dict[str, GroupThreshold]
    residual_dpd:       float                # remaining disparity after optimisation
    accuracy_overall:   float
    n_sweep_steps:      int


class ThresholdOptimizer:
    """
    Post-processing per-group threshold optimisation.

    Parameters
    ----------
    target_metric  : "demographic_parity" | "equal_opportunity" | "equalised_odds"
    min_accuracy   : Minimum individual-group accuracy to maintain.
    n_steps        : Number of threshold values to sweep (resolution).
    """

    def __init__(
        self,
        target_metric: Literal[
            "demographic_parity", "equal_opportunity", "equalised_odds"
        ] = "demographic_parity",
        min_accuracy:  float = 0.60,
        n_steps:       int   = 100,
    ):
        self._target   = target_metric
        self._min_acc  = min_accuracy
        self._n_steps  = n_steps

    def optimize(
        self,
        y_true:  List[int],
        scores:  List[float],    # predicted probabilities
        groups:  List[str],
        reference: Optional[str] = None,
    ) -> ThresholdOptimisationResult:
        n = len(y_true)
        if not (n == len(scores) == len(groups)):
            raise ValueError("y_true, scores, and groups must have the same length")

        group_data: Dict[str, List[Tuple[int, float]]] = {}
        for i in range(n):
            group_data.setdefault(groups[i], []).append((y_true[i], scores[i]))

        ref = reference or max(group_data, key=lambda g: len(group_data[g]))

        # Compute reference rate under default threshold 0.5
        ref_threshold = 0.50
        ref_metrics   = self._metrics_at(group_data[ref], ref_threshold)
        ref_rate       = (ref_metrics["tpr"] if self._target == "equal_opportunity"
                         else ref_metrics["positive_rate"])

        group_results: Dict[str, GroupThreshold] = {}
        thresholds:    Dict[str, float] = {}

        for g, data in group_data.items():
            best_t, best_gap = 0.50, float("inf")
            for step in range(self._n_steps + 1):
                t = step / self._n_steps
                m = self._metrics_at(data, t)
                if m["accuracy"] < self._min_acc:
                    continue
                rate = m["tpr"] if self._target == "equal_opportunity" else m["positive_rate"]
                gap  = abs(rate - ref_rate)
                if gap < best_gap:
                    best_gap, best_t = gap, t

            m = self._metrics_at(data, best_t)
            group_results[g] = GroupThreshold(
                group=g, threshold=round(best_t, 4),
                positive_rate=round(m["positive_rate"], 4),
                tpr=round(m["tpr"], 4),
                accuracy=round(m["accuracy"], 4),
            )
            thresholds[g] = best_t

        rates   = [gr.positive_rate for gr in group_results.values()]
        res_dpd = round(max(rates) - min(rates), 4)
        all_correct = sum(
            1 for i in range(n)
            if (scores[i] >= thresholds[groups[i]]) == bool(y_true[i])
        )
        acc_overall = round(all_correct / n, 4)

        return ThresholdOptimisationResult(
            target_metric     = self._target,
            thresholds        = thresholds,
            group_results     = group_results,
            residual_dpd      = res_dpd,
            accuracy_overall  = acc_overall,
            n_sweep_steps     = self._n_steps,
        )

    @staticmethod
    def _metrics_at(
        data: List[Tuple[int, float]], threshold: float
    ) -> Dict[str, float]:
        n       = len(data)
        preds   = [1 if s >= threshold else 0 for _, s in data]
        pos_idx = [i for i, (yt, _) in enumerate(data) if yt == 1]
        acc     = sum(preds[i] == data[i][0] for i in range(n)) / n
        pr      = sum(preds) / n
        tpr     = (sum(preds[i] for i in pos_idx) / len(pos_idx)) if pos_idx else 0.0
        return {"accuracy": acc, "positive_rate": pr, "tpr": tpr}
