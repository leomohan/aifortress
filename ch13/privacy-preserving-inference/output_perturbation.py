"""
output_perturbation.py  —  Calibrated noise addition to model outputs
AI Fortress · Chapter 13 · Code Sample 13.E

Adds Laplace or Gaussian noise to model outputs to achieve
(ε, δ)-DP inference guarantees.

Mechanisms:
  Laplace  — for pure ε-DP; noise scale = sensitivity / ε
  Gaussian — for (ε, δ)-DP; noise scale = sensitivity * √(2 ln(1.25/δ)) / ε

The sensitivity of the output depends on the model and task:
  - Probability outputs: sensitivity = 1 (bounded in [0, 1])
  - Count outputs: sensitivity = 1 per query
  - Regression outputs: sensitivity = output range
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import List, Literal, Optional


@dataclass
class PerturbedOutput:
    original:      List[float]
    perturbed:     List[float]
    mechanism:     str           # "laplace" | "gaussian"
    noise_scale:   float
    epsilon:       float
    delta:         float


class OutputPerturbation:
    """
    Adds calibrated noise to model output vectors.

    Parameters
    ----------
    epsilon      : Privacy parameter ε.
    delta        : Failure probability δ (for Gaussian mechanism).
    sensitivity  : L1/L2 sensitivity of the output.
    mechanism    : "laplace" (pure DP) or "gaussian" (approximate DP).
    seed         : Optional random seed.
    """

    def __init__(
        self,
        epsilon:     float,
        delta:       float = 1e-5,
        sensitivity: float = 1.0,
        mechanism:   Literal["laplace", "gaussian"] = "laplace",
        seed:        Optional[int] = None,
    ):
        if epsilon <= 0:
            raise ValueError("epsilon must be > 0")
        self._eps   = epsilon
        self._delta = delta
        self._sens  = sensitivity
        self._mech  = mechanism
        if seed is not None:
            random.seed(seed)

        if mechanism == "laplace":
            self._scale = sensitivity / epsilon
        else:
            self._scale = sensitivity * math.sqrt(2 * math.log(1.25 / delta)) / epsilon

    def perturb(self, outputs: List[float]) -> PerturbedOutput:
        """Add noise to a list of model output values."""
        if self._mech == "laplace":
            noisy = [v + self._laplace(self._scale) for v in outputs]
        else:
            noisy = [v + random.gauss(0, self._scale) for v in outputs]

        return PerturbedOutput(
            original    = list(outputs),
            perturbed   = noisy,
            mechanism   = self._mech,
            noise_scale = self._scale,
            epsilon     = self._eps,
            delta       = self._delta,
        )

    def perturb_batch(
        self, batch: List[List[float]]
    ) -> List[PerturbedOutput]:
        return [self.perturb(outputs) for outputs in batch]

    @staticmethod
    def _laplace(scale: float) -> float:
        """Sample from Laplace(0, scale)."""
        u = random.uniform(-0.5, 0.5)
        return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))
