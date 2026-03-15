"""
label_flip_detector.py  —  Statistical label-flip / poisoning detection
AI Fortress · Chapter 3 · Code Sample 3.A

Label-flipping attacks work by changing a fraction of training labels from
the correct class to an adversarially chosen class. This module detects:

  1. Global label-ratio anomaly  — chi-squared goodness-of-fit test against
     expected class proportions (from a trusted reference or prior audit).
  2. Per-class Z-score anomaly   — flags individual classes whose observed
     proportion deviates by more than z_threshold standard deviations.
  3. Temporal label drift        — if a timestamp column is present, tests
     whether label ratios changed significantly between time windows, which
     can indicate a targeted poisoning event at a specific ingest batch.

Reference: Biggio et al. (2012) "Poisoning Attacks against Support Vector
Machines"; Steinhardt et al. (2017) "Certified Defenses for Data Poisoning".
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from scipy import stats


@dataclass
class LabelFinding:
    detector:    str = "label_flip"
    severity:    str = "info"        # info | warning | critical
    label_col:   str = ""
    description: str = ""
    details:     dict = field(default_factory=dict)


class LabelFlipDetector:
    """
    Detects label-flipping contamination via statistical tests on class distributions.

    Parameters
    ----------
    z_threshold         : Z-score threshold for per-class anomaly (default 3.0 → ~0.1% FPR)
    chi2_alpha          : Significance level for chi-squared test (default 0.01)
    min_samples_per_class: Minimum samples required to run per-class tests
    """

    def __init__(
        self,
        z_threshold:           float = 3.0,
        chi2_alpha:            float = 0.01,
        min_samples_per_class: int   = 30,
    ):
        self.z_threshold            = z_threshold
        self.chi2_alpha             = chi2_alpha
        self.min_samples_per_class  = min_samples_per_class

    def detect(
        self,
        df:               pd.DataFrame,
        label_col:        str,
        reference_ratios: Optional[Dict[str, float]] = None,
        timestamp_col:    Optional[str] = None,
        n_time_windows:   int = 4,
    ) -> List[LabelFinding]:
        """
        Run all label-flip detection tests and return a list of findings.

        Parameters
        ----------
        reference_ratios : Expected class proportions, e.g. {"cat": 0.5, "dog": 0.5}.
                           If None, uses the empirical distribution of the first half
                           of the dataset as a reference (useful when no prior is known).
        """
        if label_col not in df.columns:
            raise ValueError(f"Column '{label_col}' not found in DataFrame")

        findings: List[LabelFinding] = []
        labels = df[label_col].dropna()
        counts = labels.value_counts()
        total  = len(labels)

        if total == 0:
            return findings

        # Build reference distribution
        if reference_ratios is None:
            # Use first half as reference — crude but usable when no prior exists
            half = len(df) // 2
            ref_counts = df.iloc[:half][label_col].value_counts()
            reference_ratios = (ref_counts / ref_counts.sum()).to_dict()

        # ── Test 1: Chi-squared goodness-of-fit ──────────────────────────────
        common_classes = [c for c in counts.index if c in reference_ratios]
        if len(common_classes) >= 2:
            observed  = np.array([counts.get(c, 0) for c in common_classes])
            expected_p = np.array([reference_ratios[c] for c in common_classes])
            expected_p = expected_p / expected_p.sum()  # normalise
            expected   = expected_p * total

            # Avoid zero expected values
            mask      = expected > 0
            if mask.sum() >= 2:
                chi2_stat, p_value = stats.chisquare(
                    f_obs=observed[mask], f_exp=expected[mask]
                )
                if p_value < self.chi2_alpha:
                    findings.append(LabelFinding(
                        severity    = "critical" if p_value < 0.001 else "warning",
                        label_col   = label_col,
                        description = (
                            f"Chi-squared test REJECTS expected label distribution "
                            f"(χ²={chi2_stat:.2f}, p={p_value:.4f} < α={self.chi2_alpha}). "
                            "Label-flipping attack or significant dataset shift suspected."
                        ),
                        details     = {
                            "chi2_stat": round(chi2_stat, 4),
                            "p_value":   round(p_value, 6),
                            "alpha":     self.chi2_alpha,
                            "classes_tested": common_classes,
                        },
                    ))

        # ── Test 2: Per-class Z-score ─────────────────────────────────────────
        for cls, ref_ratio in reference_ratios.items():
            n_cls = counts.get(cls, 0)
            if n_cls < self.min_samples_per_class:
                continue
            obs_ratio = n_cls / total
            # Standard error of observed proportion under H0
            se = np.sqrt(ref_ratio * (1 - ref_ratio) / total)
            if se == 0:
                continue
            z_score = (obs_ratio - ref_ratio) / se
            if abs(z_score) > self.z_threshold:
                findings.append(LabelFinding(
                    severity    = "critical" if abs(z_score) > 5.0 else "warning",
                    label_col   = label_col,
                    description = (
                        f"Class '{cls}' proportion anomaly: observed {obs_ratio:.3f}, "
                        f"expected {ref_ratio:.3f}, Z={z_score:.2f} "
                        f"(threshold ±{self.z_threshold})"
                    ),
                    details     = {
                        "class":        str(cls),
                        "observed":     round(obs_ratio, 4),
                        "expected":     round(ref_ratio, 4),
                        "z_score":      round(z_score, 4),
                        "sample_count": int(n_cls),
                    },
                ))

        # ── Test 3: Temporal drift (if timestamp available) ───────────────────
        if timestamp_col and timestamp_col in df.columns:
            temporal_findings = self._temporal_drift(
                df, label_col, timestamp_col, n_time_windows
            )
            findings.extend(temporal_findings)

        if not findings:
            findings.append(LabelFinding(
                severity    = "info",
                label_col   = label_col,
                description = "No label-flip anomalies detected.",
                details     = {
                    "total_samples": total,
                    "classes":       counts.to_dict(),
                },
            ))

        return findings

    def _temporal_drift(
        self,
        df:          pd.DataFrame,
        label_col:   str,
        timestamp_col: str,
        n_windows:   int,
    ) -> List[LabelFinding]:
        """Compare label distributions across equal-size time windows."""
        findings: List[LabelFinding] = []
        try:
            df_sorted = df.sort_values(timestamp_col).copy()
            window_size = len(df_sorted) // n_windows
            if window_size < 50:
                return findings

            windows = [
                df_sorted.iloc[i * window_size: (i + 1) * window_size][label_col]
                for i in range(n_windows)
            ]

            # Compare first window to each subsequent window
            ref_counts = windows[0].value_counts()
            for i, w in enumerate(windows[1:], start=1):
                w_counts = w.value_counts()
                common   = list(set(ref_counts.index) & set(w_counts.index))
                if len(common) < 2:
                    continue
                obs = np.array([w_counts.get(c, 0) for c in common])
                exp_ratio = np.array([ref_counts.get(c, 0) for c in common])
                exp_ratio = exp_ratio / exp_ratio.sum()
                exp = exp_ratio * obs.sum()
                mask = exp > 0
                if mask.sum() < 2:
                    continue
                chi2, p = stats.chisquare(obs[mask], exp[mask])
                if p < self.chi2_alpha:
                    findings.append(LabelFinding(
                        severity    = "warning",
                        label_col   = label_col,
                        description = (
                            f"Temporal label drift detected in window {i} vs window 0 "
                            f"(χ²={chi2:.2f}, p={p:.4f}). "
                            "Possible targeted batch poisoning event."
                        ),
                        details     = {"window": i, "chi2": round(chi2,4), "p_value": round(p,6)},
                    ))
        except Exception:
            pass  # Gracefully skip if timestamp parsing fails
        return findings
