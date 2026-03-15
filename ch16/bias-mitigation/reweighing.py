"""
reweighing.py  —  Pre-processing bias mitigation via sample reweighing
AI Fortress · Chapter 16 · Code Sample 16.B

Implements the Kamiran & Calders (2012) reweighing algorithm.
Assigns sample weights so that (group, label) combinations are
weighted to match their expected frequency under independence
(i.e. what you'd expect if label were independent of group).

W(x) = P_expected(group, label) / P_observed(group, label)

After reweighing, pass the weights to your model's fit() method
(e.g. sklearn's sample_weight parameter).

Reference:
  Kamiran & Calders (2012). "Data preprocessing techniques for
  classification without discrimination." KAIS.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ReweighingResult:
    weights:         List[float]       # one weight per sample
    group_label_weights: Dict[str, float]  # "(group, label)" → weight
    n_samples:       int
    n_groups:        int
    weight_range:    Tuple[float, float]   # (min, max)
    detail:          str


class Reweighing:
    """
    Pre-processing debiasing via sample weight adjustment.

    Parameters
    ----------
    privileged_group   : The group label considered privileged (e.g. "M").
                         Used only for reporting; weights are computed for all groups.
    """

    def __init__(self, privileged_group: Optional[str] = None):
        self._privileged = privileged_group

    def fit_transform(
        self,
        groups: List[str],   # protected attribute value per sample
        labels: List[int],   # ground-truth label (0/1) per sample
    ) -> ReweighingResult:
        if len(groups) != len(labels):
            raise ValueError("groups and labels must have the same length")
        n = len(groups)

        # Marginal distributions
        group_counts: Dict[str, int] = {}
        label_counts: Dict[int, int] = {}
        joint_counts: Dict[Tuple[str, int], int] = {}

        for g, lbl in zip(groups, labels):
            group_counts[g]        = group_counts.get(g, 0) + 1
            label_counts[lbl]      = label_counts.get(lbl, 0) + 1
            joint_counts[(g, lbl)] = joint_counts.get((g, lbl), 0) + 1

        # Compute weights: W = P(G) * P(Y) / P(G, Y)
        gl_weights: Dict[Tuple[str, int], float] = {}
        for (g, lbl), count in joint_counts.items():
            p_g  = group_counts[g]  / n
            p_y  = label_counts[lbl] / n
            p_gy = count / n
            gl_weights[(g, lbl)] = (p_g * p_y) / p_gy if p_gy > 0 else 1.0

        weights = [gl_weights[(g, lbl)] for g, lbl in zip(groups, labels)]
        str_weights = {f"({g},{lbl})": round(w, 4)
                       for (g, lbl), w in gl_weights.items()}

        return ReweighingResult(
            weights              = [round(w, 6) for w in weights],
            group_label_weights  = str_weights,
            n_samples            = n,
            n_groups             = len(group_counts),
            weight_range         = (round(min(weights), 4), round(max(weights), 4)),
            detail               = (
                f"Reweighing applied to {n} samples across {len(group_counts)} groups. "
                f"Weight range: [{min(weights):.4f}, {max(weights):.4f}]."
            ),
        )
