"""
radioactive_data.py  —  Dataset-level radioactive watermarking
AI Fortress · Chapter 6 · Code Sample 6.B

Embeds a statistical ownership signal into a subset of training samples
(Maini et al. 2021, "Dataset Inference"). If an attacker trains a model
on this dataset, their model will inherit the signal — detectable via a
statistical hypothesis test on a held-out verification set.

Watermark mechanism:
  1. Choose a secret direction vector p in input space (keyed by owner_secret)
  2. Select a random fraction of training samples (watermark_fraction)
  3. Add a small perturbation ε · p to each selected sample
  4. Store the (indices, direction) as the verification key

Verification:
  Given a suspect model f and the verification key:
  1. Run both clean and watermarked verification samples through f
  2. Compute the mean confidence difference: Δ = E[f(x+εp)[c] - f(x)[c]]
  3. Apply a one-sided t-test: H₀: Δ = 0, H₁: Δ > 0
  4. Reject H₀ at α = 0.01 to confirm dataset membership

This is a framework-agnostic implementation: the score_fn must be provided
externally (any callable numpy → class-probability array).
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import numpy as np
from scipy import stats


@dataclass
class RadioactiveKey:
    """Secret verification key. Keep this safe — it proves dataset ownership."""
    key_id:            str
    owner_id:          str
    direction:         List[float]    # watermark perturbation direction (p)
    epsilon:           float          # perturbation magnitude
    watermarked_indices: List[int]    # which training samples were marked
    verification_class: int           # class whose confidence is tracked
    created_at:        str

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "RadioactiveKey":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)


@dataclass
class VerificationResult:
    dataset_member:   bool          # True = model trained on watermarked data
    p_value:          float
    t_statistic:      float
    confidence_delta: float         # mean(f(x+εp) - f(x)) for verification class
    alpha:            float         # significance level used
    n_samples:        int


class RadioactiveDataWatermarker:
    """
    Embeds and verifies radioactive data watermarks.

    Parameters
    ----------
    owner_id           : Identifier of the dataset owner
    watermark_fraction : Fraction of training samples to watermark (default 0.05)
    epsilon            : Perturbation magnitude (default 0.05; must be imperceptible)
    alpha              : Significance level for verification t-test (default 0.01)
    """

    def __init__(
        self,
        owner_id:           str,
        watermark_fraction: float = 0.05,
        epsilon:            float = 0.05,
        alpha:              float = 0.01,
    ):
        self.owner_id           = owner_id
        self.watermark_fraction = watermark_fraction
        self.epsilon            = epsilon
        self.alpha              = alpha

    def embed(
        self,
        dataset: np.ndarray,       # shape (N, ...) — feature array
        labels:  np.ndarray,       # shape (N,) — class labels
        secret:  bytes,            # owner's secret for key derivation
        target_class: Optional[int] = None,
    ) -> Tuple[np.ndarray, RadioactiveKey]:
        """
        Embed watermark into `dataset`. Returns (watermarked_dataset, key).

        Parameters
        ----------
        dataset      : Training feature array (N, d)
        labels       : Training labels (N,)
        secret       : Owner secret bytes for deterministic direction generation
        target_class : Class whose confidence the watermark targets (default: majority class)
        """
        N, *dims = dataset.shape
        d        = int(np.prod(dims))

        # Derive direction vector from secret (deterministic, keyed)
        rng        = np.random.default_rng(
            int.from_bytes(hashlib.sha256(secret).digest()[:8], "big")
        )
        direction  = rng.normal(0, 1, d).astype(float)
        direction /= np.linalg.norm(direction) + 1e-12

        # Select watermark indices
        n_mark   = max(1, int(N * self.watermark_fraction))
        mark_idx = rng.choice(N, n_mark, replace=False).tolist()

        if target_class is None:
            target_class = int(np.bincount(labels.astype(int)).argmax())

        # Apply perturbation
        watermarked = dataset.copy().astype(float)
        p_reshaped  = direction.reshape(dims)
        for idx in mark_idx:
            watermarked[idx] += self.epsilon * p_reshaped
        watermarked = np.clip(watermarked, 0.0, 1.0)   # keep in valid range

        from datetime import datetime, timezone
        key = RadioactiveKey(
            key_id              = str(uuid.uuid4()),
            owner_id            = self.owner_id,
            direction           = direction.tolist(),
            epsilon             = self.epsilon,
            watermarked_indices = mark_idx,
            verification_class  = target_class,
            created_at          = datetime.now(timezone.utc).isoformat(),
        )
        return watermarked, key

    def verify(
        self,
        key:      RadioactiveKey,
        dataset:  np.ndarray,      # clean verification samples (not in training set)
        score_fn: Callable[[np.ndarray], np.ndarray],
        n_verify: int = 200,
    ) -> VerificationResult:
        """
        Test whether a suspect model was trained on the watermarked dataset.

        Parameters
        ----------
        key      : RadioactiveKey from embed()
        dataset  : Held-out clean verification samples
        score_fn : Callable: single sample array → class probability vector
        n_verify : Number of verification samples to use
        """
        direction = np.array(key.direction)
        dims      = dataset.shape[1:]
        p         = direction.reshape(dims)
        cls       = key.verification_class
        n         = min(n_verify, len(dataset))
        deltas    = []

        for x in dataset[:n]:
            x_clean = x.astype(float)
            x_mark  = np.clip(x_clean + key.epsilon * p, 0.0, 1.0)

            scores_clean = np.asarray(score_fn(x_clean), dtype=float)
            scores_mark  = np.asarray(score_fn(x_mark),  dtype=float)

            if cls < len(scores_clean) and cls < len(scores_mark):
                deltas.append(float(scores_mark[cls] - scores_clean[cls]))

        if not deltas:
            return VerificationResult(False, 1.0, 0.0, 0.0, self.alpha, 0)

        arr      = np.array(deltas)
        t_stat, p_value = stats.ttest_1samp(arr, popmean=0.0, alternative="greater")

        return VerificationResult(
            dataset_member   = bool(p_value < self.alpha),
            p_value          = round(float(p_value), 8),
            t_statistic      = round(float(t_stat), 6),
            confidence_delta = round(float(arr.mean()), 6),
            alpha            = self.alpha,
            n_samples        = len(deltas),
        )
