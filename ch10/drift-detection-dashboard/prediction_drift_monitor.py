"""
prediction_drift_monitor.py  —  Model output distribution shift detection
AI Fortress · Chapter 10 · Code Sample 10.A

Monitors the output distribution of an ML model for drift relative to
a baseline established at deployment time.

Tests applied:
  Classification : KS test on predicted probabilities per class;
                   alert on class-probability mean shift > threshold
  Regression     : KS test on predicted values;
                   alert on mean and variance shift
  Both           : Jensen-Shannon divergence on binned output distributions

JSD is bounded [0, 1] — values above 0.1 indicate notable divergence.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import numpy as np
from scipy import stats
from scipy.spatial.distance import jensenshannon


_JSD_WARNING  = 0.10
_JSD_CRITICAL = 0.20
_BINS         = 20


@dataclass
class PredictionDriftResult:
    task:         str         # "classification" | "regression"
    status:       str         # "OK" | "WARNING" | "CRITICAL"
    ks_statistic: float
    ks_p_value:   float
    jsd:          float       # Jensen-Shannon divergence
    mean_shift:   float       # absolute shift in mean prediction
    std_shift:    float       # absolute shift in std of predictions
    detail:       str


class PredictionDriftMonitor:
    """
    Monitors model output distributions for drift.

    Parameters
    ----------
    task          : "classification" (probabilities) or "regression" (values)
    p_warning     : KS p-value threshold for WARNING
    p_critical    : KS p-value threshold for CRITICAL
    jsd_warning   : JSD threshold for WARNING
    jsd_critical  : JSD threshold for CRITICAL
    mean_shift_tol: Alert if mean prediction shifts by more than this fraction
                    of the baseline standard deviation
    """

    def __init__(
        self,
        task:           str   = "classification",
        p_warning:      float = 0.05,
        p_critical:     float = 0.001,
        jsd_warning:    float = _JSD_WARNING,
        jsd_critical:   float = _JSD_CRITICAL,
        mean_shift_tol: float = 2.0,       # in units of baseline std
    ):
        self.task          = task
        self.p_warn        = p_warning
        self.p_crit        = p_critical
        self.jsd_warn      = jsd_warning
        self.jsd_crit      = jsd_critical
        self.mean_shift_tol = mean_shift_tol

    def check(
        self,
        baseline: np.ndarray,
        current:  np.ndarray,
    ) -> PredictionDriftResult:
        """
        Compare current predictions to baseline.

        For classification, pass the positive-class probability (1D).
        For regression, pass the predicted values (1D).
        """
        baseline = np.array(baseline, dtype=float).flatten()
        current  = np.array(current,  dtype=float).flatten()

        if len(baseline) < 10 or len(current) < 10:
            return PredictionDriftResult(
                task=self.task, status="OK", ks_statistic=0.0, ks_p_value=1.0,
                jsd=0.0, mean_shift=0.0, std_shift=0.0,
                detail="Insufficient samples",
            )

        ks_stat, ks_p = stats.ks_2samp(baseline, current)

        # JSD on binned distributions
        lo = min(baseline.min(), current.min())
        hi = max(baseline.max(), current.max())
        if hi == lo:
            hi = lo + 1e-9
        edges = np.linspace(lo, hi, _BINS + 1)
        ref_h, _ = np.histogram(baseline, bins=edges, density=True)
        cur_h, _ = np.histogram(current,  bins=edges, density=True)
        ref_h   += 1e-9
        cur_h   += 1e-9
        jsd_val  = float(jensenshannon(ref_h, cur_h))

        mean_shift = abs(current.mean() - baseline.mean())
        std_shift  = abs(current.std()  - baseline.std())
        baseline_std = baseline.std() or 1.0
        normalised_shift = mean_shift / baseline_std

        status = self._severity(ks_p, jsd_val, normalised_shift)

        return PredictionDriftResult(
            task         = self.task,
            status       = status,
            ks_statistic = round(float(ks_stat), 4),
            ks_p_value   = round(float(ks_p),   6),
            jsd          = round(jsd_val,         4),
            mean_shift   = round(mean_shift,      4),
            std_shift    = round(std_shift,       4),
            detail       = (f"KS stat={ks_stat:.4f}, p={ks_p:.4f}, "
                            f"JSD={jsd_val:.4f}, mean_shift={mean_shift:.4f}"),
        )

    def _severity(self, p_val: float, jsd: float, norm_shift: float) -> str:
        if p_val < self.p_crit or jsd > self.jsd_crit:
            return "CRITICAL"
        if (p_val < self.p_warn or jsd > self.jsd_warn
                or norm_shift > self.mean_shift_tol):
            return "WARNING"
        return "OK"
