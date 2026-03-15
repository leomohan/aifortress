"""
input_smoothing.py  —  Randomised smoothing with certified radius
AI Fortress · Chapter 5 · Code Sample 5.B

Implements the Cohen et al. (2019) randomised smoothing certification scheme.

Core idea:
  Given a base classifier f and Gaussian noise σ, define a smoothed classifier g:
    g(x) = argmax_c  P[f(x + ε) = c]  where ε ~ N(0, σ²I)

  If the top class wins with probability p_A > 0.5 under the noise, then g is
  certified to be robust within an ℓ₂ ball of radius:
    R = σ · Φ⁻¹(p_A)
  where Φ⁻¹ is the inverse standard normal CDF.

  Any adversarial perturbation with ℓ₂ norm < R is guaranteed NOT to change
  the smoothed classifier's prediction — provably, not just empirically.

Design:
  - Framework-agnostic: accepts a score_fn callable (numpy → numpy)
  - Supports classification (argmax over class probabilities)
  - Uses Clopper-Pearson confidence interval for a conservative p_A estimate
  - Returns ABSTAIN when the lower bound on p_A ≤ 0.5 (certifiably uncertain)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

import numpy as np
from scipy import stats


ABSTAIN = -1   # Sentinel: smoothed classifier abstains (cannot certify)


@dataclass
class SmoothingResult:
    prediction:        int           # Predicted class (-1 = ABSTAIN)
    certified_radius:  float         # ℓ₂ certification radius (0.0 if ABSTAIN)
    p_a_lower:         float         # Clopper-Pearson lower bound on P[top class]
    top_class_count:   int           # Votes for top class out of n_samples
    n_samples:         int
    abstained:         bool


class RandomisedSmoother:
    """
    Certifiably robust inference via randomised smoothing (Cohen et al. 2019).

    Parameters
    ----------
    sigma      : Gaussian noise standard deviation. Larger σ → larger certified
                 radius but lower clean accuracy. Typical values: 0.12, 0.25, 0.50.
    n_samples  : Number of noisy copies to use for prediction (default 100).
                 For final certification use n_samples ≥ 1000.
    confidence : Confidence level for Clopper-Pearson interval (default 0.999).
    """

    def __init__(
        self,
        sigma:      float = 0.25,
        n_samples:  int   = 100,
        confidence: float = 0.999,
    ):
        self.sigma      = sigma
        self.n_samples  = n_samples
        self.confidence = confidence

    def predict(
        self,
        x:        np.ndarray,
        score_fn: Callable[[np.ndarray], np.ndarray],
        n_classes: int = 0,
    ) -> int:
        """Fast prediction (no certification). Returns predicted class."""
        counts = self._sample_counts(x, score_fn, self.n_samples, n_classes)
        return int(np.argmax(counts))

    def predict_and_certify(
        self,
        x:        np.ndarray,
        score_fn: Callable[[np.ndarray], np.ndarray],
        n_classes: int = 0,
    ) -> SmoothingResult:
        """
        Predict and compute the certified ℓ₂ robustness radius.

        Returns a SmoothingResult. If prediction.abstained is True, the
        classifier could not certify with the given confidence — treat as
        uncertain and do NOT return the prediction to the caller.
        """
        counts    = self._sample_counts(x, score_fn, self.n_samples, n_classes)
        top_class = int(np.argmax(counts))
        top_count = int(counts[top_class])

        # Clopper-Pearson lower bound on p_A
        p_a_lower = self._clopper_pearson_lower(top_count, self.n_samples, self.confidence)

        if p_a_lower <= 0.5:
            return SmoothingResult(
                prediction       = ABSTAIN,
                certified_radius = 0.0,
                p_a_lower        = p_a_lower,
                top_class_count  = top_count,
                n_samples        = self.n_samples,
                abstained        = True,
            )

        radius = float(self.sigma * stats.norm.ppf(p_a_lower))
        return SmoothingResult(
            prediction       = top_class,
            certified_radius = radius,
            p_a_lower        = p_a_lower,
            top_class_count  = top_count,
            n_samples        = self.n_samples,
            abstained        = False,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _sample_counts(
        self,
        x:        np.ndarray,
        score_fn: Callable[[np.ndarray], np.ndarray],
        n:        int,
        n_classes: int,
    ) -> np.ndarray:
        """
        Sample n noisy versions of x, run score_fn on each, tally class votes.
        score_fn must accept a single sample array and return either:
          - a 1-D probability/logit array (class scores), or
          - a scalar int (class label)
        """
        vote_counts: Optional[np.ndarray] = None

        for _ in range(n):
            noise   = np.random.normal(0, self.sigma, size=x.shape).astype(x.dtype)
            x_noisy = x + noise
            output  = score_fn(x_noisy)

            # Normalise output to class index
            if isinstance(output, (int, np.integer)):
                pred = int(output)
                if vote_counts is None:
                    n_cls = max(n_classes, pred + 1)
                    vote_counts = np.zeros(n_cls, dtype=int)
                elif pred >= len(vote_counts):
                    vote_counts = np.concatenate(
                        [vote_counts, np.zeros(pred + 1 - len(vote_counts), dtype=int)]
                    )
                vote_counts[pred] += 1
            else:
                output = np.asarray(output)
                if vote_counts is None:
                    vote_counts = np.zeros(len(output), dtype=int)
                vote_counts[int(np.argmax(output))] += 1

        return vote_counts if vote_counts is not None else np.zeros(1, dtype=int)

    @staticmethod
    def _clopper_pearson_lower(k: int, n: int, confidence: float) -> float:
        """
        Clopper-Pearson (exact) lower confidence bound for a binomial proportion.
        Returns the lower end of the (confidence)-level interval for p,
        given k successes in n trials.
        """
        if k == 0:
            return 0.0
        alpha = 1.0 - confidence
        # Lower bound from beta distribution quantile
        return float(stats.beta.ppf(alpha / 2, k, n - k + 1))
