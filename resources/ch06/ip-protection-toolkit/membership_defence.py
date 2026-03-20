"""
membership_defence.py  —  Confidence score DP noise injection
AI Fortress · Chapter 6 · Code Sample 6.C

Defends against membership inference attacks by adding calibrated
Laplace or Gaussian noise to confidence scores before returning them
to the caller (complements Chapter 5 output_sanitiser.py).

Follows the framework of Jia et al. (2019) — MemGuard and
the DP-prediction approach of Lecuyer et al. (2019).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np


@dataclass
class MembershipDefenceResult:
    original_probs:  np.ndarray
    defended_probs:  np.ndarray
    noise_mechanism: str
    epsilon_dp:      float
    clipped:         bool


class MembershipDefence:
    """
    Adds calibrated noise to output probabilities to defend against
    membership inference attacks.

    Parameters
    ----------
    epsilon_dp   : Differential privacy budget ε (smaller = more private).
                   Typical values: 1.0 (strong), 5.0 (moderate), 10.0 (light).
    mechanism    : "laplace" | "gaussian"
    clip_to_simplex : Re-normalise noisy probs to sum to 1 (default True)
    """

    def __init__(
        self,
        epsilon_dp:      float = 5.0,
        mechanism:       str   = "laplace",
        clip_to_simplex: bool  = True,
    ):
        self.epsilon_dp     = epsilon_dp
        self.mechanism      = mechanism
        self.clip_to_simplex = clip_to_simplex

    def defend(self, probs: np.ndarray) -> MembershipDefenceResult:
        """
        Add noise to `probs` and return a MembershipDefenceResult.
        The sensitivity of the probability vector under ℓ₁ is 2 (changing
        one training point can shift any probability by at most 1/N, but
        we use a conservative sensitivity of 1.0 here for the local DP setting).
        """
        probs    = np.array(probs, dtype=float)
        n        = len(probs)
        sensitivity = 1.0   # ℓ₁ sensitivity of softmax probabilities

        if self.mechanism == "laplace":
            scale = sensitivity / self.epsilon_dp
            noise = np.random.laplace(0, scale, n)
        elif self.mechanism == "gaussian":
            # For (ε, δ)-DP with δ=1e-5
            delta = 1e-5
            sigma = sensitivity * np.sqrt(2 * np.log(1.25 / delta)) / self.epsilon_dp
            noise = np.random.normal(0, sigma, n)
        else:
            raise ValueError(f"Unknown mechanism '{self.mechanism}'")

        noisy = probs + noise

        # Clip to [0, 1]
        noisy = np.clip(noisy, 0.0, 1.0)
        clipped = True

        # Re-normalise to simplex
        if self.clip_to_simplex:
            total = noisy.sum()
            if total > 0:
                noisy = noisy / total

        return MembershipDefenceResult(
            original_probs  = probs,
            defended_probs  = noisy,
            noise_mechanism = self.mechanism,
            epsilon_dp      = self.epsilon_dp,
            clipped         = clipped,
        )

    def defend_top_k(self, probs: np.ndarray, k: int = 3) -> np.ndarray:
        """Return only top-k class probabilities with noise — stronger defence."""
        probs = np.array(probs, dtype=float)
        top_k = np.argsort(probs)[::-1][:k]
        result = self.defend(probs)
        masked = np.zeros_like(result.defended_probs)
        for i in top_k:
            masked[i] = result.defended_probs[i]
        total = masked.sum()
        return masked / total if total > 0 else masked
