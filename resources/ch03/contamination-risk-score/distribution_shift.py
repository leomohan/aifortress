"""
distribution_shift.py  —  MMD and KS-test distribution shift detection
AI Fortress · Chapter 3 · Code Sample 3.A

Detects covariate shift between a trusted reference dataset and a new
dataset batch. Two complementary tests are implemented:

  1. Kolmogorov-Smirnov (KS) test — per-feature, non-parametric test for
     distributional equality. Sensitive to changes in shape, mean, and tail.

  2. Maximum Mean Discrepancy (MMD) — kernel-based two-sample test on the
     joint feature distribution. Uses an RBF kernel with the median
     heuristic for bandwidth selection (Gretton et al. 2012).

A significant shift (p < alpha on multiple features, or large MMD) indicates
that new data may have been collected from a different distribution — caused
by natural drift, adversarial injection, or pipeline misconfiguration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.preprocessing import StandardScaler


@dataclass
class ShiftFinding:
    detector:    str = "distribution_shift"
    severity:    str = "info"
    feature:     str = ""
    description: str = ""
    details:     dict = field(default_factory=dict)


class DistributionShiftDetector:
    """
    Detects distribution shift between a reference and current dataset.

    Parameters
    ----------
    ks_alpha         : KS-test significance level (default 0.01; Bonferroni
                       correction applied automatically across features)
    mmd_threshold    : MMD statistic threshold above which shift is flagged
    min_samples      : Minimum samples in each split to run tests
    """

    def __init__(
        self,
        ks_alpha:      float = 0.01,
        mmd_threshold: float = 0.05,
        min_samples:   int   = 100,
    ):
        self.ks_alpha      = ks_alpha
        self.mmd_threshold = mmd_threshold
        self.min_samples   = min_samples

    def detect(
        self,
        reference_df: pd.DataFrame,
        current_df:   pd.DataFrame,
        feature_cols: Optional[List[str]] = None,
    ) -> List[ShiftFinding]:
        """
        Compare distributions of reference and current datasets.

        Returns a list of ShiftFinding objects; an 'info' finding is appended
        when no shift is detected.
        """
        findings: List[ShiftFinding] = []

        if len(reference_df) < self.min_samples or len(current_df) < self.min_samples:
            findings.append(ShiftFinding(
                severity    = "info",
                description = f"Insufficient samples for shift detection "
                              f"(reference={len(reference_df)}, current={len(current_df)}, "
                              f"min={self.min_samples}).",
            ))
            return findings

        cols = feature_cols or [
            c for c in reference_df.columns
            if c in current_df.columns and reference_df[c].dtype in [np.float64, np.float32,
                                                                       np.int64, np.int32]
        ]
        if not cols:
            findings.append(ShiftFinding(
                severity="info", description="No numeric feature columns available for shift detection."
            ))
            return findings

        # Bonferroni-corrected alpha
        alpha_corrected = self.ks_alpha / len(cols)
        shifted_features: List[str] = []

        # ── KS tests per feature ──────────────────────────────────────────────
        for col in cols:
            ref = reference_df[col].dropna().values.astype(float)
            cur = current_df[col].dropna().values.astype(float)
            if len(ref) < 10 or len(cur) < 10:
                continue
            ks_stat, p_value = stats.ks_2samp(ref, cur)
            if p_value < alpha_corrected:
                shifted_features.append(col)
                severity = "critical" if p_value < 1e-6 else "warning"
                findings.append(ShiftFinding(
                    severity    = severity,
                    feature     = col,
                    description = (
                        f"Feature '{col}': KS test detects significant distribution shift "
                        f"(D={ks_stat:.4f}, p={p_value:.2e} < α_corr={alpha_corrected:.2e})."
                    ),
                    details     = {
                        "ks_stat":          round(float(ks_stat), 6),
                        "p_value":          round(float(p_value), 8),
                        "alpha_corrected":  round(alpha_corrected, 6),
                        "ref_mean":         round(float(ref.mean()), 4),
                        "cur_mean":         round(float(cur.mean()), 4),
                        "ref_std":          round(float(ref.std()), 4),
                        "cur_std":          round(float(cur.std()), 4),
                    },
                ))

        # ── MMD on joint distribution ─────────────────────────────────────────
        try:
            mmd_val = self._compute_mmd(reference_df[cols], current_df[cols])
            if mmd_val > self.mmd_threshold:
                findings.append(ShiftFinding(
                    severity    = "critical" if mmd_val > self.mmd_threshold * 3 else "warning",
                    feature     = "joint",
                    description = (
                        f"MMD test detects joint distribution shift across {len(cols)} features "
                        f"(MMD={mmd_val:.4f} > threshold {self.mmd_threshold})."
                    ),
                    details     = {
                        "mmd":            round(float(mmd_val), 6),
                        "threshold":      self.mmd_threshold,
                        "features_used":  cols,
                        "shifted_features": shifted_features,
                    },
                ))
        except Exception:
            pass  # MMD is a nice-to-have; don't fail if it errors

        if not any(f.severity in ("warning", "critical") for f in findings):
            findings.append(ShiftFinding(
                severity    = "info",
                description = f"No significant distribution shift detected across {len(cols)} features.",
                details     = {"features_tested": len(cols), "alpha_corrected": round(alpha_corrected, 6)},
            ))

        return findings

    def _compute_mmd(
        self,
        ref_df: pd.DataFrame,
        cur_df: pd.DataFrame,
        max_samples: int = 500,
    ) -> float:
        """
        Unbiased MMD² estimate using RBF kernel with median bandwidth heuristic.
        Subsample to max_samples for performance.
        """
        scaler = StandardScaler()
        ref    = scaler.fit_transform(ref_df.dropna().values.astype(float))
        cur    = scaler.transform(cur_df.dropna().values.astype(float))

        # Subsample for performance
        rng = np.random.default_rng(42)
        if len(ref) > max_samples:
            ref = ref[rng.choice(len(ref), max_samples, replace=False)]
        if len(cur) > max_samples:
            cur = cur[rng.choice(len(cur), max_samples, replace=False)]

        # Median heuristic for RBF bandwidth
        combined = np.vstack([ref, cur])
        dists    = np.sum((combined[:, None, :] - combined[None, :, :]) ** 2, axis=-1)
        bandwidth = float(np.median(dists[dists > 0])) / 2.0
        if bandwidth == 0:
            return 0.0

        def rbf_kernel(A: np.ndarray, B: np.ndarray) -> np.ndarray:
            d = np.sum((A[:, None, :] - B[None, :, :]) ** 2, axis=-1)
            return np.exp(-d / bandwidth)

        kxx = rbf_kernel(ref, ref)
        kyy = rbf_kernel(cur, cur)
        kxy = rbf_kernel(ref, cur)

        m, n = len(ref), len(cur)
        mmd2 = (kxx.sum() - np.trace(kxx)) / (m * (m - 1)) \
             + (kyy.sum() - np.trace(kyy)) / (n * (n - 1)) \
             - 2 * kxy.mean()
        return float(max(mmd2, 0.0)) ** 0.5
