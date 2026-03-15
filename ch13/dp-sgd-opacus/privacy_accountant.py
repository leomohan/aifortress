"""
privacy_accountant.py  —  RDP moment accountant for DP-SGD
AI Fortress · Chapter 13 · Code Sample 13.A

Implements a simplified Rényi Differential Privacy (RDP) accountant
for computing the (ε, δ)-DP guarantee of DP-SGD training.

Based on:
  - Mironov (2017). "Rényi Differential Privacy of the Gaussian Mechanism"
  - Wang et al. (2019). "Subsampled Rényi Differential Privacy"
  - Balle et al. (2020). "Hypothesis Testing Interpretations and Renormalization"

The RDP orders (alpha values) used here follow the standard Opacus defaults.
For production systems use the full Opacus accountant; this is an educational
implementation demonstrating the accounting pipeline.

Conversion: RDP(α, ε_α) → (ε, δ)-DP via:
  ε = ε_α + log(1 - 1/α) - log(δ * (α-1)) / (α-1)  (Proposition 3, Balle 2020)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# RDP orders used for accountant evaluation
_DEFAULT_ALPHAS = [
    1.5, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0,
    11.0, 12.0, 13.0, 14.0, 15.0, 16.0, 17.0, 18.0, 19.0, 20.0,
    25.0, 50.0, 100.0, 256.0, 512.0,
]


def _rdp_gaussian(alpha: float, sigma: float, q: float) -> float:
    """
    RDP of the Gaussian mechanism with subsampling (Poisson, rate q).
    Approximation valid for small q (q ≪ 1).
    """
    if alpha == 1.0:
        return q * q / (2 * sigma * sigma)
    # Simplified bound for alpha > 1:
    return min(
        alpha * q * q / (2 * sigma * sigma),                        # second-order bound
        (alpha / (alpha - 1)) * math.log(                           # tighter bound
            (1 - q) + q * math.exp((alpha - 1) * alpha / (2 * sigma * sigma))
        ),
    )


def _rdp_to_dp(rdp_eps: float, alpha: float, delta: float) -> float:
    """Convert RDP guarantee to (ε, δ)-DP via Balle et al. (2020)."""
    if alpha <= 1 or rdp_eps < 0:
        return float("inf")
    try:
        return rdp_eps + (
            math.log(1 - 1 / alpha) - math.log(delta * (alpha - 1))
        ) / (alpha - 1)
    except (ValueError, ZeroDivisionError):
        return float("inf")


@dataclass
class AccountantState:
    steps:           int = 0
    rdp_budgets:     List[float] = field(default_factory=list)   # per alpha
    noise_multiplier: float = 0.0
    sample_rate:     float = 0.0
    delta:           float = 0.0


class RDPAccountant:
    """
    Moment accountant for (ε, δ)-DP tracking of DP-SGD.

    Parameters
    ----------
    noise_multiplier : σ — noise multiplier.
    sample_rate      : q — batch_size / dataset_size.
    delta            : δ — target failure probability.
    alphas           : RDP orders to track. Defaults to standard set.
    """

    def __init__(
        self,
        noise_multiplier: float,
        sample_rate:      float,
        delta:            float,
        alphas:           Optional[List[float]] = None,
    ):
        self._sigma   = noise_multiplier
        self._q       = sample_rate
        self._delta   = delta
        self._alphas  = alphas or _DEFAULT_ALPHAS
        self._rdp     = [0.0] * len(self._alphas)
        self._steps   = 0

    def compose(self, n_steps: int = 1) -> None:
        """Add n_steps of DP-SGD to the running RDP budget."""
        for _ in range(n_steps):
            for i, alpha in enumerate(self._alphas):
                self._rdp[i] += _rdp_gaussian(alpha, self._sigma, self._q)
        self._steps += n_steps

    def get_epsilon(self) -> float:
        """Return the current (ε, δ)-DP guarantee (minimum over all alpha orders)."""
        eps_candidates = [
            _rdp_to_dp(rdp, alpha, self._delta)
            for alpha, rdp in zip(self._alphas, self._rdp)
        ]
        return min(eps_candidates)

    def get_epsilon_at_delta(self, delta: float) -> float:
        """Compute epsilon for a different delta value."""
        eps_candidates = [
            _rdp_to_dp(rdp, alpha, delta)
            for alpha, rdp in zip(self._alphas, self._rdp)
        ]
        return min(eps_candidates)

    def steps_to_budget(self, target_epsilon: float) -> int:
        """
        Estimate how many more steps can be taken before target_epsilon is exceeded.
        Uses binary search over step counts.
        """
        current_eps = self.get_epsilon()
        if current_eps >= target_epsilon:
            return 0

        lo, hi = 0, 10_000
        while lo < hi:
            mid = (lo + hi + 1) // 2
            probe = RDPAccountant(self._sigma, self._q, self._delta, self._alphas)
            probe.compose(self._steps + mid)
            if probe.get_epsilon() <= target_epsilon:
                lo = mid
            else:
                hi = mid - 1
        return lo

    @property
    def steps_taken(self) -> int:
        return self._steps

    def state(self) -> AccountantState:
        return AccountantState(
            steps            = self._steps,
            rdp_budgets      = list(self._rdp),
            noise_multiplier = self._sigma,
            sample_rate      = self._q,
            delta            = self._delta,
        )
