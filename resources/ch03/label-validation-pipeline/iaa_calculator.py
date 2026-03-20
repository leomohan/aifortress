"""
iaa_calculator.py  —  Inter-annotator agreement (IAA) metrics
AI Fortress · Chapter 3 · Code Sample 3.B

Implements three complementary IAA metrics:

  Cohen's Kappa (κ)     — pairwise agreement corrected for chance (two annotators)
  Fleiss' Kappa (κ_F)   — multi-annotator generalisation of Cohen's κ
  Krippendorff's Alpha  — handles missing data, multiple annotators, ordinal scales

Interpretation thresholds (Landis & Koch 1977):
  κ < 0.00  → Poor
  κ 0.00-0.20 → Slight
  κ 0.21-0.40 → Fair
  κ 0.41-0.60 → Moderate
  κ 0.61-0.80 → Substantial
  κ 0.81-1.00 → Almost perfect
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import cohen_kappa_score


@dataclass
class IAAResult:
    metric:         str
    value:          float
    interpretation: str
    n_samples:      int
    n_classes:      int
    details:        dict


def _interpret_kappa(k: float) -> str:
    if k < 0.00: return "Poor (worse than chance)"
    if k < 0.21: return "Slight"
    if k < 0.41: return "Fair"
    if k < 0.61: return "Moderate"
    if k < 0.81: return "Substantial"
    return "Almost perfect"


class IAACalculator:
    """Computes inter-annotator agreement metrics for label quality assessment."""

    def cohens_kappa(
        self,
        labels_a: pd.Series,
        labels_b: pd.Series,
        weights:  Optional[str] = None,   # None | "linear" | "quadratic"
    ) -> IAAResult:
        """
        Cohen's Kappa for two annotators.

        Parameters
        ----------
        weights : None for nominal categories; "linear" or "quadratic" for ordinal.
        """
        # Align and drop NaN pairs
        df = pd.DataFrame({"a": labels_a, "b": labels_b}).dropna()
        if len(df) < 2:
            raise ValueError("Need at least 2 paired labels for Cohen's Kappa")

        kappa = cohen_kappa_score(df["a"], df["b"], weights=weights)
        classes = sorted(set(df["a"].unique()) | set(df["b"].unique()))

        # Per-class agreement breakdown
        per_class = {}
        for cls in classes:
            agree = int(((df["a"] == cls) & (df["b"] == cls)).sum())
            total_a = int((df["a"] == cls).sum())
            total_b = int((df["b"] == cls).sum())
            per_class[str(cls)] = {"agree": agree, "ann_a": total_a, "ann_b": total_b}

        return IAAResult(
            metric         = "cohens_kappa",
            value          = round(float(kappa), 4),
            interpretation = _interpret_kappa(kappa),
            n_samples      = len(df),
            n_classes      = len(classes),
            details        = {"weights": weights, "per_class": per_class},
        )

    def fleiss_kappa(
        self,
        ratings_matrix: np.ndarray,
    ) -> IAAResult:
        """
        Fleiss' Kappa for multiple annotators.

        Parameters
        ----------
        ratings_matrix : (n_subjects, n_categories) array where each cell
                         contains the number of annotators assigning that
                         category to that subject.
        """
        N, k = ratings_matrix.shape
        n    = ratings_matrix[0].sum()   # ratings per subject

        p_j  = ratings_matrix.sum(axis=0) / (N * n)    # marginal proportions
        P_i  = ((ratings_matrix ** 2).sum(axis=1) - n) / (n * (n - 1))
        P_bar = P_i.mean()
        P_e   = (p_j ** 2).sum()

        if P_e == 1.0:
            kappa = 1.0
        else:
            kappa = (P_bar - P_e) / (1 - P_e)

        return IAAResult(
            metric         = "fleiss_kappa",
            value          = round(float(kappa), 4),
            interpretation = _interpret_kappa(kappa),
            n_samples      = N,
            n_classes      = k,
            details        = {
                "n_annotators_per_subject": int(n),
                "marginal_proportions": p_j.tolist(),
            },
        )

    def krippendorffs_alpha(
        self,
        reliability_data: List[List[Optional[float]]],
        level_of_measurement: str = "nominal",
    ) -> IAAResult:
        """
        Krippendorff's Alpha.

        Parameters
        ----------
        reliability_data : List of annotator rating vectors.
                           Each inner list has one entry per subject; None for missing.
        level_of_measurement : "nominal" | "ordinal" | "interval" | "ratio"
        """
        # Convert to numpy with NaN for missing
        data = np.array(
            [[np.nan if v is None else float(v) for v in row]
             for row in reliability_data]
        )   # shape: (n_annotators, n_units)

        def _metric_diff(a: float, b: float) -> float:
            if level_of_measurement == "nominal":
                return 0.0 if a == b else 1.0
            if level_of_measurement == "ordinal":
                return (a - b) ** 2   # simplified; proper ordinal uses rank sums
            return (a - b) ** 2   # interval / ratio

        # Flatten all valid pairs
        n_u = data.shape[1]
        do  = 0.0   # observed disagreement
        de  = 0.0   # expected disagreement
        n_pairs = 0

        for u in range(n_u):
            unit_vals = data[:, u][~np.isnan(data[:, u])]
            m_u = len(unit_vals)
            if m_u < 2:
                continue
            for i in range(m_u):
                for j in range(i + 1, m_u):
                    do += _metric_diff(unit_vals[i], unit_vals[j])
                    n_pairs += 1

        # Expected disagreement from all values
        all_vals = data[~np.isnan(data)]
        n_v = len(all_vals)
        if n_v < 2:
            alpha = 1.0
        else:
            for i in range(n_v):
                for j in range(i + 1, n_v):
                    de += _metric_diff(all_vals[i], all_vals[j])
            de_norm = de / (n_v * (n_v - 1))
            do_norm = do / n_pairs if n_pairs > 0 else 0.0
            alpha   = 1 - (do_norm / de_norm) if de_norm > 0 else 1.0

        return IAAResult(
            metric         = "krippendorffs_alpha",
            value          = round(float(alpha), 4),
            interpretation = _interpret_kappa(alpha),
            n_samples      = n_u,
            n_classes      = len(set(all_vals.tolist())),
            details        = {
                "level_of_measurement": level_of_measurement,
                "n_annotators": data.shape[0],
            },
        )

    def annotator_disagreement_report(
        self,
        annotations: pd.DataFrame,
        annotator_cols: List[str],
    ) -> dict:
        """
        For a DataFrame with one column per annotator, find samples with
        highest disagreement (useful for re-annotation prioritisation).
        """
        def _row_agreement(row: pd.Series) -> float:
            vals = row.dropna()
            if len(vals) < 2:
                return 1.0
            mode_count = vals.value_counts().iloc[0]
            return float(mode_count) / len(vals)

        agreement = annotations[annotator_cols].apply(_row_agreement, axis=1)
        low_agree  = agreement[agreement < 0.6]

        return {
            "n_total":          len(annotations),
            "n_disagreed":      len(low_agree),
            "disagree_ratio":   round(len(low_agree) / len(annotations), 4),
            "mean_agreement":   round(float(agreement.mean()), 4),
            "worst_indices":    low_agree.nsmallest(10).index.tolist(),
        }
