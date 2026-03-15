"""
backdoor_detector.py  —  Backdoor / trojan trigger pattern detection
AI Fortress · Chapter 3 · Code Sample 3.A

Backdoor attacks embed a trigger pattern (pixel patch, text phrase, audio
tone) in a subset of training samples and associate it with a target class.
The model learns to classify any input containing the trigger as the target.

This detector looks for the STATISTICAL SIGNATURE of a backdoor without
needing to run the model:

  1. Target-class feature clustering — samples labelled as the target class
     are clustered. A suspiciously tight, separate cluster may indicate
     triggered samples (Chen et al. 2019 "Detecting Backdoor Attacks").

  2. Spectral signature detection — the top singular vectors of the feature
     covariance matrix for the target class are examined for anomalous
     separation (Tran et al. 2018 "Spectral Signatures in Backdoor Attacks").

  3. Activation clustering heuristic (tabular proxy) — samples in the
     target class are split into two clusters via K-Means on their features.
     A significant size imbalance (one cluster << other) suggests a small
     poisoned cohort.

Note: These are dataset-level heuristics. A dedicated model-level analysis
(activation clustering on hidden layer representations) provides higher
confidence. See companion site for model-level extensions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import TruncatedSVD


@dataclass
class BackdoorFinding:
    detector:    str = "backdoor"
    severity:    str = "info"
    target_class: str = ""
    description:  str = ""
    details:      dict = field(default_factory=dict)


class BackdoorDetector:
    """
    Dataset-level backdoor / trojan trigger detection.

    Parameters
    ----------
    min_poison_ratio  : Minimum fraction of target-class samples that could
                        constitute a backdoor cohort (default 0.01 = 1%)
    cluster_imbalance_threshold : Ratio of smaller/larger cluster size below
                        which activation clustering flags a finding (default 0.15)
    spectral_gap_threshold : Threshold on the top-2 singular value gap
    """

    def __init__(
        self,
        min_poison_ratio:            float = 0.01,
        cluster_imbalance_threshold: float = 0.15,
        spectral_gap_threshold:      float = 2.0,
    ):
        self.min_poison_ratio            = min_poison_ratio
        self.cluster_imbalance_threshold = cluster_imbalance_threshold
        self.spectral_gap_threshold      = spectral_gap_threshold

    def detect(
        self,
        df:            pd.DataFrame,
        feature_cols:  List[str],
        label_col:     str,
        target_class:  Optional[str] = None,
    ) -> List[BackdoorFinding]:
        """
        Scan for backdoor signatures in feature space.

        Parameters
        ----------
        target_class : The suspected target class the backdoor causes predictions to be.
                       If None, runs detection on all classes and returns the worst finding.
        """
        findings: List[BackdoorFinding] = []
        classes = [target_class] if target_class else df[label_col].unique().tolist()

        for cls in classes:
            cls_df = df[df[label_col] == cls][feature_cols].dropna()
            if len(cls_df) < max(20, int(len(df) * self.min_poison_ratio * 2)):
                continue

            X = StandardScaler().fit_transform(cls_df.values.astype(float))

            # ── Test 1: Activation clustering (K-Means imbalance) ─────────────
            kmeans    = KMeans(n_clusters=2, n_init=10, random_state=42)
            cluster_labels = kmeans.fit_predict(X)
            c0, c1    = np.sum(cluster_labels == 0), np.sum(cluster_labels == 1)
            smaller   = min(c0, c1)
            larger    = max(c0, c1)
            imbalance = smaller / larger if larger > 0 else 1.0

            if imbalance < self.cluster_imbalance_threshold:
                poison_fraction = smaller / len(X)
                findings.append(BackdoorFinding(
                    severity     = "critical" if poison_fraction > 0.05 else "warning",
                    target_class = str(cls),
                    description  = (
                        f"Class '{cls}': K-Means activation clustering reveals a "
                        f"suspiciously small sub-cluster of {smaller} samples "
                        f"({poison_fraction:.1%} of class). "
                        "Pattern consistent with a backdoor trigger cohort."
                    ),
                    details      = {
                        "cluster_sizes":   [int(c0), int(c1)],
                        "imbalance_ratio": round(imbalance, 4),
                        "poison_fraction": round(poison_fraction, 4),
                    },
                ))

            # ── Test 2: Spectral signature ────────────────────────────────────
            if X.shape[0] >= 10 and X.shape[1] >= 2:
                n_components = min(5, X.shape[1], X.shape[0] - 1)
                svd  = TruncatedSVD(n_components=n_components, random_state=42)
                svd.fit(X)
                svals = svd.singular_values_
                if len(svals) >= 2 and svals[1] > 0:
                    gap = svals[0] / svals[1]
                    if gap > self.spectral_gap_threshold:
                        findings.append(BackdoorFinding(
                            severity     = "warning",
                            target_class = str(cls),
                            description  = (
                                f"Class '{cls}': Spectral analysis reveals anomalous "
                                f"top singular value gap (σ₁/σ₂ = {gap:.2f} > "
                                f"threshold {self.spectral_gap_threshold}). "
                                "Consistent with spectral signature of a backdoor attack."
                            ),
                            details      = {
                                "singular_values": [round(float(s), 4) for s in svals],
                                "gap_ratio":       round(float(gap), 4),
                            },
                        ))

        if not findings:
            findings.append(BackdoorFinding(
                severity    = "info",
                description = "No backdoor trigger signatures detected.",
                details     = {"classes_analysed": [str(c) for c in classes]},
            ))
        return findings
