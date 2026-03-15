"""
fidelity_evaluator.py  —  Fidelity evaluation for DP synthetic data
AI Fortress · Chapter 13 · Code Sample 13.C

Measures statistical fidelity between real and synthetic datasets:
  - Per-column mean absolute error
  - Per-column std dev absolute error
  - Correlation matrix Frobenius distance
  - Marginal distribution overlap (histogram intersection)
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ColumnFidelity:
    name:        str
    mean_error:  float    # |real_mean - synth_mean|
    std_error:   float    # |real_std  - synth_std|
    overlap:     float    # histogram intersection ∈ [0, 1]


@dataclass
class FidelityReport:
    n_real:               int
    n_synthetic:          int
    column_fidelity:      List[ColumnFidelity]
    mean_error_avg:       float    # average across columns
    std_error_avg:        float
    correlation_distance: float    # Frobenius distance of correlation matrices
    overall_score:        float    # 0 = identical, higher = less similar
    grade:                str      # "A" | "B" | "C" | "D"

    def summary(self) -> str:
        return (
            f"Fidelity grade {self.grade}: "
            f"mean_err={self.mean_error_avg:.4f}, "
            f"std_err={self.std_error_avg:.4f}, "
            f"corr_dist={self.correlation_distance:.4f}"
        )


class FidelityEvaluator:
    """Evaluates statistical fidelity of synthetic vs real data."""

    def evaluate(
        self,
        real:      List[Dict[str, float]],
        synthetic: List[Dict[str, float]],
        n_bins:    int = 20,
    ) -> FidelityReport:
        if not real or not synthetic:
            raise ValueError("Both real and synthetic datasets must be non-empty")
        columns = list(real[0].keys())

        col_fidelity: List[ColumnFidelity] = []
        for col in columns:
            r_vals = [r[col] for r in real]
            s_vals = [r[col] for r in synthetic]
            mean_err = abs(statistics.mean(r_vals) - statistics.mean(s_vals))
            std_err  = abs(
                (statistics.pstdev(r_vals) or 0) - (statistics.pstdev(s_vals) or 0)
            )
            overlap = self._histogram_overlap(r_vals, s_vals, n_bins)
            col_fidelity.append(ColumnFidelity(col, round(mean_err, 6),
                                               round(std_err, 6), round(overlap, 4)))

        mean_err_avg = statistics.mean(c.mean_error for c in col_fidelity)
        std_err_avg  = statistics.mean(c.std_error  for c in col_fidelity)
        corr_dist    = self._correlation_distance(real, synthetic, columns)
        score        = mean_err_avg + std_err_avg + corr_dist
        grade        = "A" if score < 0.1 else "B" if score < 0.5 else \
                       "C" if score < 1.0 else "D"

        return FidelityReport(
            n_real               = len(real),
            n_synthetic          = len(synthetic),
            column_fidelity      = col_fidelity,
            mean_error_avg       = round(mean_err_avg, 6),
            std_error_avg        = round(std_err_avg, 6),
            correlation_distance = round(corr_dist, 6),
            overall_score        = round(score, 6),
            grade                = grade,
        )

    @staticmethod
    def _histogram_overlap(a: List[float], b: List[float], n_bins: int) -> float:
        lo = min(min(a), min(b))
        hi = max(max(a), max(b))
        if hi == lo:
            return 1.0
        width = (hi - lo) / n_bins

        def to_hist(vals):
            counts = [0] * n_bins
            for v in vals:
                idx = min(int((v - lo) / width), n_bins - 1)
                counts[idx] += 1
            total = len(vals)
            return [c / total for c in counts]

        ha, hb = to_hist(a), to_hist(b)
        return sum(min(ha[i], hb[i]) for i in range(n_bins))

    @staticmethod
    def _correlation_distance(
        real: List[Dict[str, float]],
        synth: List[Dict[str, float]],
        columns: List[str],
    ) -> float:
        def corr_matrix(data):
            vals = {c: [r[c] for r in data] for c in columns}
            n_col = len(columns)
            mat = [[0.0] * n_col for _ in range(n_col)]
            for i, ci in enumerate(columns):
                for j, cj in enumerate(columns):
                    if i == j:
                        mat[i][j] = 1.0
                    else:
                        try:
                            mat[i][j] = statistics.correlation(vals[ci], vals[cj])
                        except Exception:
                            mat[i][j] = 0.0
            return mat

        if len(columns) < 2:
            return 0.0
        rm = corr_matrix(real)
        sm = corr_matrix(synth)
        frob = math.sqrt(
            sum((rm[i][j] - sm[i][j]) ** 2
                for i in range(len(columns)) for j in range(len(columns)))
        )
        return frob
