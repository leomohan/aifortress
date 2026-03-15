"""
confidence_cleaner.py  —  Confidence-based mislabel detection
AI Fortress · Chapter 3 · Code Sample 3.B

Uses cross-validated predicted probabilities to identify samples whose
assigned label is inconsistent with what the model learned from the rest
of the dataset.  Inspired by the confident learning framework (Northcutt et al.,
"Confident Learning: Estimating Uncertainty in Dataset Labels", JAIR 2021).

Approach:
  1. Fit a fast classifier (Logistic Regression by default) using k-fold CV.
  2. Collect out-of-fold predicted probabilities for every sample.
  3. For each class c, compute the per-class threshold: the average predicted
     probability for samples that are labelled c.
  4. A sample is flagged as a potential mislabel if its predicted class
     (argmax of probabilities) differs from its given label AND its
     predicted probability for the true label falls below the class threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.base import BaseEstimator


@dataclass
class CleaningResult:
    noisy_indices:     List[int]
    noise_rate:        float
    n_samples:         int
    n_classes:         int
    per_class_noise:   dict      # class → estimated noise fraction
    details:           dict = field(default_factory=dict)


class ConfidenceCleaner:
    """
    Cross-validation confidence-based label noise detector.

    Parameters
    ----------
    classifier    : sklearn-compatible classifier with predict_proba.
                    Defaults to LogisticRegression (fast, interpretable).
    n_splits      : Number of CV folds (default 5)
    n_jobs        : Parallelism for CV (default -1 = all cores)
    """

    def __init__(
        self,
        classifier: Optional[BaseEstimator] = None,
        n_splits:   int = 5,
        n_jobs:     int = -1,
    ):
        self.classifier = classifier or LogisticRegression(
            max_iter=1000, n_jobs=n_jobs, random_state=42
        )
        self.n_splits   = n_splits
        self.n_jobs     = n_jobs

    def find_noisy_labels(
        self,
        X:           np.ndarray | pd.DataFrame,
        y:           np.ndarray | pd.Series,
        return_probs: bool = False,
    ) -> CleaningResult:
        """
        Identify likely mislabelled samples.

        Parameters
        ----------
        X : Feature matrix (n_samples, n_features)
        y : Label vector (n_samples,)

        Returns
        -------
        CleaningResult with indices of suspected mislabels
        """
        if isinstance(X, pd.DataFrame):
            X = X.values
        X = np.asarray(X, dtype=float)

        le = LabelEncoder()
        y_enc = le.fit_transform(np.asarray(y))
        classes = le.classes_
        n, n_classes = len(y_enc), len(classes)

        # Scale features
        scaler = StandardScaler()
        X_sc   = scaler.fit_transform(X)

        # ── Cross-validated predicted probabilities ────────────────────────
        probs = np.zeros((n, n_classes))
        skf   = StratifiedKFold(n_splits=self.n_splits, shuffle=True, random_state=42)

        for train_idx, val_idx in skf.split(X_sc, y_enc):
            self.classifier.fit(X_sc[train_idx], y_enc[train_idx])
            probs[val_idx] = self.classifier.predict_proba(X_sc[val_idx])

        # ── Per-class confidence thresholds ───────────────────────────────
        thresholds = np.zeros(n_classes)
        for c in range(n_classes):
            mask = y_enc == c
            if mask.sum() > 0:
                thresholds[c] = probs[mask, c].mean()

        # ── Flag mislabels ─────────────────────────────────────────────────
        predicted = probs.argmax(axis=1)
        noisy_mask = np.zeros(n, dtype=bool)
        for i in range(n):
            true_class = y_enc[i]
            if predicted[i] != true_class:
                # Predicted class differs; check if prob for true class is below threshold
                if probs[i, true_class] < thresholds[true_class]:
                    noisy_mask[i] = True

        noisy_indices = np.where(noisy_mask)[0].tolist()
        noise_rate    = len(noisy_indices) / n

        # Per-class noise rate
        per_class_noise: dict = {}
        for c, cls_name in enumerate(classes):
            cls_mask = y_enc == c
            cls_noisy = noisy_mask[cls_mask].sum()
            cls_total = cls_mask.sum()
            per_class_noise[str(cls_name)] = {
                "noisy":      int(cls_noisy),
                "total":      int(cls_total),
                "noise_rate": round(cls_noisy / cls_total, 4) if cls_total > 0 else 0.0,
            }

        return CleaningResult(
            noisy_indices   = noisy_indices,
            noise_rate      = round(noise_rate, 4),
            n_samples       = n,
            n_classes       = n_classes,
            per_class_noise = per_class_noise,
            details         = {
                "classifier":  type(self.classifier).__name__,
                "n_splits":    self.n_splits,
                "thresholds":  {str(cls): round(float(t), 4)
                                for cls, t in zip(classes, thresholds)},
            },
        )

    def clean_dataframe(
        self,
        df:          pd.DataFrame,
        feature_cols: List[str],
        label_col:   str,
    ) -> Tuple[pd.DataFrame, CleaningResult]:
        """
        Remove suspected mislabelled rows from a DataFrame.
        Returns (cleaned_df, CleaningResult).
        """
        X = df[feature_cols].values
        y = df[label_col].values
        result = self.find_noisy_labels(X, y)
        clean_df = df.drop(index=df.index[result.noisy_indices]).reset_index(drop=True)
        return clean_df, result
