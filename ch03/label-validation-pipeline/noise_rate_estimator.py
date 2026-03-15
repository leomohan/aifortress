"""
noise_rate_estimator.py  —  Confident learning noise-rate estimation
AI Fortress · Chapter 3 · Code Sample 3.B

Estimates the fraction of mislabelled samples per class using the
confident learning framework (Northcutt et al. 2021).

Key concept: the joint distribution of noisy (given) labels and true labels
can be estimated from the out-of-fold predicted probabilities.  The
off-diagonal entries of this joint matrix represent the estimated number of
samples where the given label is s̃ but the true label is s.

This gives:
  - Estimated noise transition matrix T[s̃, s] = P(ŷ = s̃ | y = s)
  - Per-class noise rates (fraction of class that is mislabelled)
  - Global dataset noise rate estimate
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler


@dataclass
class NoiseRateResult:
    global_noise_rate:   float
    per_class_noise:     dict          # class_name → estimated noise fraction
    transition_matrix:   List[List[float]]   # T[given, true]
    n_samples:           int
    classes:             List[str]
    details:             dict


class NoiseRateEstimator:
    """
    Estimates dataset noise rates using the confident learning framework.

    Parameters
    ----------
    n_splits    : CV folds for probability estimation
    calibrate   : Apply isotonic regression calibration to probabilities
    """

    def __init__(self, n_splits: int = 5, calibrate: bool = False):
        self.n_splits  = n_splits
        self.calibrate = calibrate

    def estimate(
        self,
        X: np.ndarray | pd.DataFrame,
        y: np.ndarray | pd.Series,
    ) -> NoiseRateResult:
        """Estimate noise rates from features X and noisy labels y."""
        if isinstance(X, pd.DataFrame):
            X = X.values
        X = np.asarray(X, dtype=float)

        le    = LabelEncoder()
        y_enc = le.fit_transform(np.asarray(y))
        classes    = le.classes_
        n_classes  = len(classes)
        n          = len(y_enc)

        # Get cross-validated probabilities
        probs  = self._get_cv_probs(X, y_enc, n_classes)

        # ── Confident learning: build joint distribution ───────────────────
        # Per-class thresholds (mean prob for samples labelled as that class)
        thresholds = np.array([
            probs[y_enc == c, c].mean() if (y_enc == c).sum() > 0 else 0.5
            for c in range(n_classes)
        ])

        # Count confident joint: C[given, true]
        C = np.zeros((n_classes, n_classes), dtype=float)
        for i in range(n):
            given_class = y_enc[i]
            # A sample is "confidently" assigned to class j if its prob exceeds threshold j
            for j in range(n_classes):
                if probs[i, j] >= thresholds[j]:
                    C[given_class, j] += probs[i, j]

        # Normalise to get joint distribution, then scale to counts
        C_sum = C.sum()
        if C_sum == 0:
            C_sum = 1.0
        Q_noisy = np.array([(y_enc == c).sum() / n for c in range(n_classes)])
        C_norm  = C / C_sum

        # Scale each row by the marginal count of the given class
        joint = np.zeros_like(C)
        for s in range(n_classes):
            row_sum = C_norm[s].sum()
            if row_sum > 0:
                joint[s] = C_norm[s] / row_sum * (y_enc == s).sum()

        # Noise transition matrix: T[given, true]
        transition = np.zeros((n_classes, n_classes))
        for s in range(n_classes):
            row_sum = joint[s].sum()
            if row_sum > 0:
                transition[s] = joint[s] / row_sum

        # Per-class noise: 1 - T[c, c]  (diagonal = "clean" fraction)
        per_class_noise: dict = {}
        for c, cls_name in enumerate(classes):
            noise = max(0.0, 1.0 - float(transition[c, c]))
            per_class_noise[str(cls_name)] = round(noise, 4)

        global_noise = float(np.sum(joint) - np.trace(joint)) / n

        return NoiseRateResult(
            global_noise_rate  = round(max(0.0, global_noise), 4),
            per_class_noise    = per_class_noise,
            transition_matrix  = [[round(float(v), 4) for v in row] for row in transition],
            n_samples          = n,
            classes            = [str(c) for c in classes],
            details            = {
                "n_splits":    self.n_splits,
                "thresholds":  {str(cls): round(float(t), 4)
                                for cls, t in zip(classes, thresholds)},
            },
        )

    def _get_cv_probs(
        self,
        X:        np.ndarray,
        y_enc:    np.ndarray,
        n_classes: int,
    ) -> np.ndarray:
        scaler = StandardScaler()
        X_sc   = scaler.fit_transform(X)
        probs  = np.zeros((len(y_enc), n_classes))
        clf    = LogisticRegression(max_iter=1000, random_state=42)
        skf    = StratifiedKFold(n_splits=self.n_splits, shuffle=True, random_state=42)
        for train_idx, val_idx in skf.split(X_sc, y_enc):
            clf.fit(X_sc[train_idx], y_enc[train_idx])
            probs[val_idx] = clf.predict_proba(X_sc[val_idx])
        return probs
