"""
gaussian_synthesiser.py  —  DP tabular data synthesiser
AI Fortress · Chapter 13 · Code Sample 13.C

Generates differentially private synthetic tabular records by:
  1. Computing column-wise mean and std dev from real data
  2. Adding Laplace noise calibrated to (ε, δ) on the statistics
  3. Sampling synthetic records from N(noisy_mean, noisy_std²) per column

This is a simplified demonstration of the statistics-release + sampling
approach. For production use, consider CTGAN+DP, PrivSyn, or MST.

Privacy guarantee:
  Adding Gaussian noise with σ = Δf * √(2 ln(1.25/δ)) / ε gives (ε, δ)-DP
  where Δf is the sensitivity of the statistic (mean sensitivity = range/N).
"""
from __future__ import annotations

import math
import random
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ColumnStats:
    name:       str
    mean:       float
    std:        float
    min_val:    float
    max_val:    float
    n:          int


@dataclass
class SyntheticDataset:
    records:     List[Dict[str, float]]
    epsilon:     float
    delta:       float
    n_real:      int
    n_synthetic: int
    column_names: List[str]

    def column(self, name: str) -> List[float]:
        return [r[name] for r in self.records]


class GaussianDPSynthesiser:
    """
    Differentially private tabular data synthesiser.

    Parameters
    ----------
    epsilon : Privacy budget ε.
    delta   : Failure probability δ.
    seed    : Optional random seed for reproducibility.
    """

    def __init__(self, epsilon: float, delta: float, seed: Optional[int] = None):
        if epsilon <= 0:
            raise ValueError("epsilon must be > 0")
        if not (0 < delta < 1):
            raise ValueError("delta must be in (0, 1)")
        self._eps   = epsilon
        self._delta = delta
        if seed is not None:
            random.seed(seed)

    def fit_transform(
        self,
        data:          List[Dict[str, float]],
        n_synthetic:   int,
        clip_bounds:   Optional[Dict[str, Tuple[float, float]]] = None,
    ) -> SyntheticDataset:
        """
        Fit noisy statistics to data and generate n_synthetic records.

        Parameters
        ----------
        data        : List of dicts, each dict is one record with float values.
        n_synthetic : Number of synthetic records to generate.
        clip_bounds : Optional dict of column → (min, max) for clipping before
                      stat computation (reduces sensitivity).
        """
        if not data:
            raise ValueError("data must not be empty")
        columns = list(data[0].keys())
        n       = len(data)

        # Compute noisy statistics per column
        noisy_stats: Dict[str, ColumnStats] = {}
        for col in columns:
            vals = [r[col] for r in data]
            if clip_bounds and col in clip_bounds:
                lo, hi = clip_bounds[col]
                vals = [max(lo, min(hi, v)) for v in vals]
                col_range = hi - lo
            else:
                col_range = max(vals) - min(vals) + 1e-9

            true_mean = statistics.mean(vals)
            true_std  = statistics.pstdev(vals) or 1e-6

            # Sensitivity of mean = range / n
            sensitivity_mean = col_range / n
            sigma = sensitivity_mean * math.sqrt(2 * math.log(1.25 / self._delta)) / self._eps

            noisy_mean = true_mean + random.gauss(0, sigma)
            noisy_std  = max(1e-6, true_std + random.gauss(0, sigma))

            noisy_stats[col] = ColumnStats(
                name=col, mean=noisy_mean, std=noisy_std,
                min_val=min(vals), max_val=max(vals), n=n,
            )

        # Sample synthetic records
        records = []
        for _ in range(n_synthetic):
            rec = {
                col: random.gauss(s.mean, s.std)
                for col, s in noisy_stats.items()
            }
            records.append(rec)

        return SyntheticDataset(
            records      = records,
            epsilon      = self._eps,
            delta        = self._delta,
            n_real       = n,
            n_synthetic  = n_synthetic,
            column_names = columns,
        )
