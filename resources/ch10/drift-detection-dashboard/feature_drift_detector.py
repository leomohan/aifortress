"""
feature_drift_detector.py  —  Statistical feature drift detection for ML models
AI Fortress · Chapter 10 · Code Sample 10.A

Detects statistical drift in model input features between a reference
(baseline) distribution and a current production window.

Tests applied per feature:
  Continuous : Kolmogorov-Smirnov two-sample test (p-value + statistic)
               Population Stability Index (PSI) over 10 equal-frequency bins
  Categorical: Chi-squared goodness-of-fit test (p-value + statistic)
               New-category detection (categories in current absent from baseline)

Drift severity tiers (configurable):
  CRITICAL  : p-value < 0.001  OR  PSI > 0.25
  WARNING   : p-value < 0.05   OR  PSI > 0.10
  OK        : no significant drift detected
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import stats


_PSI_BINS          = 10
_PSI_EPSILON       = 1e-6   # avoid log(0)


def _psi(reference: np.ndarray, current: np.ndarray, bins: int = _PSI_BINS) -> float:
    """Population Stability Index for continuous features."""
    # Use reference quantiles for bin edges
    quantiles  = np.linspace(0, 100, bins + 1)
    bin_edges  = np.percentile(reference, quantiles)
    bin_edges  = np.unique(bin_edges)
    if len(bin_edges) < 2:
        return 0.0

    ref_counts, _ = np.histogram(reference, bins=bin_edges)
    cur_counts, _ = np.histogram(current,   bins=bin_edges)

    ref_pct = ref_counts / len(reference) + _PSI_EPSILON
    cur_pct = cur_counts / len(current)   + _PSI_EPSILON

    psi = np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))
    return float(psi)


@dataclass
class FeatureDriftResult:
    feature:    str
    dtype:      str           # "continuous" | "categorical"
    status:     str           # "OK" | "WARNING" | "CRITICAL"
    test:       str           # "ks" | "chi2"
    statistic:  float
    p_value:    float
    psi:        float         # PSI for continuous; 0.0 for categorical
    new_categories: List[str] # categories in current absent from baseline
    detail:     str


@dataclass
class FeatureDriftReport:
    total_features:  int
    drifted:         int       # WARNING + CRITICAL
    critical:        int
    warning:         int
    ok:              int
    results:         List[FeatureDriftResult]
    overall_pass:    bool      # True if no CRITICAL features

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} Feature drift: {self.drifted}/{self.total_features} features drifted "
            f"({self.critical} CRITICAL, {self.warning} WARNING)."
        )


class FeatureDriftDetector:
    """
    Detects statistical drift in ML input features.

    Parameters
    ----------
    p_critical   : p-value threshold for CRITICAL drift (default 0.001)
    p_warning    : p-value threshold for WARNING drift (default 0.05)
    psi_critical : PSI threshold for CRITICAL drift (default 0.25)
    psi_warning  : PSI threshold for WARNING drift (default 0.10)
    """

    def __init__(
        self,
        p_critical:   float = 0.001,
        p_warning:    float = 0.05,
        psi_critical: float = 0.25,
        psi_warning:  float = 0.10,
    ):
        self.p_crit  = p_critical
        self.p_warn  = p_warning
        self.psi_crit = psi_critical
        self.psi_warn = psi_warning

    def detect(
        self,
        reference: Dict[str, list],
        current:   Dict[str, list],
        dtypes:    Optional[Dict[str, str]] = None,
    ) -> FeatureDriftReport:
        """
        Detect drift for all features present in both reference and current.

        Parameters
        ----------
        reference : Dict of feature_name → list of reference values
        current   : Dict of feature_name → list of current window values
        dtypes    : Optional dict of feature_name → "continuous"|"categorical".
                    Auto-detected if not provided.
        """
        results: List[FeatureDriftResult] = []
        features = set(reference.keys()) & set(current.keys())

        for feat in sorted(features):
            ref_vals = np.array(reference[feat])
            cur_vals = np.array(current[feat])
            dtype    = (dtypes or {}).get(feat) or self._infer_dtype(ref_vals)
            result   = self._test_feature(feat, ref_vals, cur_vals, dtype)
            results.append(result)

        critical = sum(1 for r in results if r.status == "CRITICAL")
        warning  = sum(1 for r in results if r.status == "WARNING")
        ok       = sum(1 for r in results if r.status == "OK")

        return FeatureDriftReport(
            total_features = len(results),
            drifted        = critical + warning,
            critical       = critical,
            warning        = warning,
            ok             = ok,
            results        = results,
            overall_pass   = critical == 0,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _test_feature(
        self,
        feat:     str,
        ref:      np.ndarray,
        cur:      np.ndarray,
        dtype:    str,
    ) -> FeatureDriftResult:
        ref = ref[~self._is_nan(ref)]
        cur = cur[~self._is_nan(cur)]

        if len(ref) < 10 or len(cur) < 10:
            return FeatureDriftResult(
                feature=feat, dtype=dtype, status="OK", test="none",
                statistic=0.0, p_value=1.0, psi=0.0, new_categories=[],
                detail="Insufficient samples for testing",
            )

        if dtype == "categorical":
            return self._chi2_test(feat, ref, cur)
        else:
            return self._ks_test(feat, ref.astype(float), cur.astype(float))

    def _ks_test(self, feat: str, ref: np.ndarray, cur: np.ndarray) -> FeatureDriftResult:
        stat, p_val = stats.ks_2samp(ref, cur)
        psi_val     = _psi(ref, cur)
        status      = self._severity_continuous(p_val, psi_val)
        return FeatureDriftResult(
            feature=feat, dtype="continuous", status=status,
            test="ks", statistic=round(float(stat), 4), p_value=round(float(p_val), 6),
            psi=round(psi_val, 4), new_categories=[],
            detail=(f"KS stat={stat:.4f}, p={p_val:.4f}, PSI={psi_val:.4f}"),
        )

    def _chi2_test(self, feat: str, ref: np.ndarray, cur: np.ndarray) -> FeatureDriftResult:
        ref_cats    = set(ref.tolist())
        cur_cats    = set(cur.tolist())
        new_cats    = sorted(str(c) for c in cur_cats - ref_cats)
        all_cats    = sorted(ref_cats | cur_cats)

        ref_counts  = np.array([np.sum(ref == c) for c in all_cats], dtype=float)
        cur_counts  = np.array([np.sum(cur == c) for c in all_cats], dtype=float)

        # Normalise reference to expected counts
        expected    = ref_counts / ref_counts.sum() * cur_counts.sum()
        expected    = np.where(expected == 0, _PSI_EPSILON, expected)

        stat, p_val = stats.chisquare(cur_counts, f_exp=expected)
        status      = self._severity_categorical(p_val, new_cats)
        return FeatureDriftResult(
            feature=feat, dtype="categorical", status=status,
            test="chi2", statistic=round(float(stat), 4), p_value=round(float(p_val), 6),
            psi=0.0, new_categories=new_cats,
            detail=(f"Chi2 stat={stat:.4f}, p={p_val:.4f}, "
                    f"new_cats={len(new_cats)}"),
        )

    def _severity_continuous(self, p_val: float, psi: float) -> str:
        if p_val < self.p_crit or psi > self.psi_crit:
            return "CRITICAL"
        if p_val < self.p_warn or psi > self.psi_warn:
            return "WARNING"
        return "OK"

    def _severity_categorical(self, p_val: float, new_cats: list) -> str:
        if p_val < self.p_crit or len(new_cats) > 0:
            return "CRITICAL" if p_val < self.p_crit else "WARNING"
        if p_val < self.p_warn:
            return "WARNING"
        return "OK"

    @staticmethod
    def _infer_dtype(arr: np.ndarray) -> str:
        try:
            arr.astype(float)
            return "continuous"
        except (ValueError, TypeError):
            return "categorical"

    @staticmethod
    def _is_nan(arr: np.ndarray) -> np.ndarray:
        try:
            return np.isnan(arr.astype(float))
        except (ValueError, TypeError):
            return np.zeros(len(arr), dtype=bool)
