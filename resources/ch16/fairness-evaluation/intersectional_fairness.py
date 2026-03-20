"""
intersectional_fairness.py  —  Intersectional fairness analysis
AI Fortress · Chapter 16 · Code Sample 16.A

Extends standard group fairness to intersectional subgroups
(e.g. gender × race, age × disability). Identifies subgroups
that appear fair in aggregate but are disadvantaged at the intersection.

Kearns et al. (2018) "Preventing Fairness Gerrymandering" showed that
satisfying group fairness for each attribute independently does not
guarantee fairness for intersectional subgroups.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from fairness_metrics import FairnessEvaluator, GroupMetrics


@dataclass
class IntersectionalGroup:
    attributes:    Dict[str, str]   # e.g. {"gender": "F", "age_band": "55+"}
    label:         str              # e.g. "F×55+"
    n:             int
    positive_rate: float
    tpr:           float
    fpr:           float


@dataclass
class IntersectionalFairnessReport:
    n_subgroups:        int
    min_positive_rate:  float
    max_positive_rate:  float
    parity_range:       float       # max - min positive rate
    worst_subgroup:     str
    best_subgroup:      str
    subgroups:          List[IntersectionalGroup]
    violations:         List[str]
    grade:              str


class IntersectionalFairnessEvaluator:
    """
    Evaluates fairness across all combinations of multiple protected attributes.

    Parameters
    ----------
    min_subgroup_size  : Subgroups smaller than this are excluded (too few samples).
    parity_threshold   : Maximum allowed positive rate range across subgroups.
    """

    def __init__(self, min_subgroup_size: int = 30, parity_threshold: float = 0.10):
        self._min_size = min_subgroup_size
        self._parity_thr = parity_threshold

    def evaluate(
        self,
        y_true:     List[int],
        y_pred:     List[int],
        attributes: Dict[str, List[str]],   # attr_name → list of values per record
    ) -> IntersectionalFairnessReport:
        n = len(y_true)
        attr_names = list(attributes.keys())

        # Build intersectional group index
        group_data: Dict[str, List[Tuple[int, int]]] = {}
        for i in range(n):
            key = "×".join(f"{a}={attributes[a][i]}" for a in attr_names)
            group_data.setdefault(key, []).append((y_true[i], y_pred[i]))

        subgroups: List[IntersectionalGroup] = []
        for label, data in group_data.items():
            if len(data) < self._min_size:
                continue
            yt = [d[0] for d in data]
            yp = [d[1] for d in data]
            nn = len(data)
            pr = sum(yp) / nn
            pos_idx = [i for i, t in enumerate(yt) if t == 1]
            neg_idx = [i for i, t in enumerate(yt) if t == 0]
            tpr = sum(yp[i] for i in pos_idx) / len(pos_idx) if pos_idx else 0.0
            fpr = sum(yp[i] for i in neg_idx) / len(neg_idx) if neg_idx else 0.0

            attrs_dict = {
                a: attributes[a][
                    next(i for i in range(n)
                         if "×".join(f"{aa}={attributes[aa][i]}" for aa in attr_names) == label)
                ]
                for a in attr_names
            }
            subgroups.append(IntersectionalGroup(
                attributes=attrs_dict, label=label, n=nn,
                positive_rate=round(pr, 4), tpr=round(tpr, 4), fpr=round(fpr, 4),
            ))

        if not subgroups:
            return IntersectionalFairnessReport(
                n_subgroups=0, min_positive_rate=0, max_positive_rate=0,
                parity_range=0, worst_subgroup="", best_subgroup="",
                subgroups=[], violations=["No subgroups meet min_subgroup_size"], grade="F",
            )

        prs = [s.positive_rate for s in subgroups]
        min_pr = min(prs)
        max_pr = max(prs)
        rng    = max_pr - min_pr
        worst  = min(subgroups, key=lambda s: s.positive_rate).label
        best   = max(subgroups, key=lambda s: s.positive_rate).label

        violations: List[str] = []
        if rng > self._parity_thr:
            violations.append(
                f"Parity range {rng:.3f} exceeds threshold {self._parity_thr} "
                f"across {len(subgroups)} intersectional subgroups."
            )

        grade = "A" if rng < 0.05 else "B" if rng < 0.10 else \
                "C" if rng < 0.15 else "D" if rng < 0.20 else "F"

        return IntersectionalFairnessReport(
            n_subgroups=len(subgroups), min_positive_rate=round(min_pr, 4),
            max_positive_rate=round(max_pr, 4), parity_range=round(rng, 4),
            worst_subgroup=worst, best_subgroup=best,
            subgroups=subgroups, violations=violations, grade=grade,
        )
