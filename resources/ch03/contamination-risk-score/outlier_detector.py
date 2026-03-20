"""
outlier_detector.py  —  Isolation Forest + Z-score outlier detection
AI Fortress · Chapter 3 · Code Sample 3.A
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


@dataclass
class OutlierFinding:
    detector:     str = "outlier"
    severity:     str = "info"
    description:  str = ""
    details:      dict = field(default_factory=dict)


class OutlierDetector:
    """
    Detects statistical outliers via Isolation Forest and per-feature Z-score.

    Parameters
    ----------
    contamination     : Expected fraction of outliers (IF parameter; default 0.05)
    z_threshold       : Per-feature Z-score threshold (default 4.0)
    max_outlier_ratio : Fraction above which outlier count triggers a finding
    """

    def __init__(
        self,
        contamination:     float = 0.05,
        z_threshold:       float = 4.0,
        max_outlier_ratio: float = 0.08,
    ):
        self.contamination     = contamination
        self.z_threshold       = z_threshold
        self.max_outlier_ratio = max_outlier_ratio

    def detect(
        self,
        df:           pd.DataFrame,
        feature_cols: Optional[List[str]] = None,
    ) -> List[OutlierFinding]:
        findings: List[OutlierFinding] = []
        cols = feature_cols or [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
        X    = df[cols].dropna().values.astype(float)

        if len(X) < 20:
            return [OutlierFinding(severity="info", description="Too few samples for outlier detection.")]

        scaler = StandardScaler()
        X_sc   = scaler.fit_transform(X)

        # ── Isolation Forest ──────────────────────────────────────────────────
        iso   = IsolationForest(contamination=self.contamination, random_state=42, n_jobs=-1)
        preds = iso.fit_predict(X_sc)   # -1 = outlier, 1 = inlier
        n_outliers = int((preds == -1).sum())
        outlier_ratio = n_outliers / len(X)

        if outlier_ratio > self.max_outlier_ratio:
            findings.append(OutlierFinding(
                severity    = "warning",
                description = (
                    f"Isolation Forest flagged {n_outliers} outliers "
                    f"({outlier_ratio:.1%} > threshold {self.max_outlier_ratio:.1%}). "
                    "Adversarially injected outliers can bias model decision boundaries."
                ),
                details     = {
                    "n_outliers":    n_outliers,
                    "outlier_ratio": round(outlier_ratio, 4),
                    "contamination_param": self.contamination,
                },
            ))

        # ── Per-feature Z-score ───────────────────────────────────────────────
        extreme_features: List[str] = []
        for i, col in enumerate(cols):
            col_z = np.abs(X_sc[:, i])
            n_extreme = int((col_z > self.z_threshold).sum())
            if n_extreme > 0:
                extreme_features.append(col)
                findings.append(OutlierFinding(
                    severity    = "warning",
                    feature     = col,
                    description = (
                        f"Feature '{col}': {n_extreme} values exceed Z-score threshold "
                        f"±{self.z_threshold} (max Z = {col_z.max():.2f})."
                    ),
                    details     = {
                        "feature":      col,
                        "n_extreme":    n_extreme,
                        "max_z_score":  round(float(col_z.max()), 4),
                        "threshold":    self.z_threshold,
                    },
                ))

        if not findings:
            findings.append(OutlierFinding(
                severity    = "info",
                description = f"No significant outliers detected across {len(cols)} features.",
                details     = {"features_tested": len(cols), "n_rows": len(X)},
            ))

        return findings
