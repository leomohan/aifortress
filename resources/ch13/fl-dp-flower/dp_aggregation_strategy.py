"""
dp_aggregation_strategy.py  —  DP-FedAvg server aggregation strategy
AI Fortress · Chapter 13 · Code Sample 13.B

Implements a differentially private federated averaging strategy.
For each aggregation round:
  1. Clip each client's model update (Δw) to L2 norm ≤ S (sensitivity bound)
  2. Sum the clipped updates
  3. Add Gaussian noise with std = noise_multiplier * S to the sum
  4. Divide by the number of participating clients (or a fixed normaliser)

This gives (ε, δ)-DP per round. Total budget over T rounds follows
sequential composition: ε_total ≈ √(T * ln(1/δ)) * ε_per_round for
simple composition; use the accountant for tighter bounds.

The strategy is framework-agnostic at the core (no flwr import at
module level); the FlowerDPStrategy subclass adds the Flower interface.
"""
from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class DPAggregationConfig:
    noise_multiplier:     float    # σ — noise std dev relative to clip bound
    clip_bound:           float    # S — per-client update L2 clip bound
    min_clients:          int = 2  # minimum clients for DP amplification
    fixed_normaliser:     Optional[int] = None  # if set, divide by this instead of n_clients
    target_delta:         float = 1e-5

    def validate(self) -> None:
        if self.noise_multiplier < 0:
            raise ValueError("noise_multiplier must be ≥ 0")
        if self.clip_bound <= 0:
            raise ValueError("clip_bound must be > 0")
        if self.min_clients < 1:
            raise ValueError("min_clients must be ≥ 1")


@dataclass
class AggregationResult:
    round_num:       int
    n_clients:       int
    clipped_count:   int
    noise_added:     bool
    aggregate:       List[float]   # aggregated (noisy) update
    epsilon_round:   float         # per-round privacy cost estimate


class DPAggregator:
    """
    Core DP aggregation logic (framework-independent).

    Operates on lists of floats representing flattened model parameter deltas.
    """

    def __init__(
        self,
        config:     DPAggregationConfig,
        audit_path: Optional[str | Path] = None,
    ):
        config.validate()
        self.config     = config
        self._round_num = 0
        self._audit     = Path(audit_path) if audit_path else None

    def aggregate(
        self,
        client_updates: List[List[float]],
    ) -> AggregationResult:
        """
        Clip, sum, add noise, and normalise client model updates.

        Parameters
        ----------
        client_updates : List of flattened model update vectors, one per client.

        Returns
        -------
        AggregationResult with the noisy aggregate.
        """
        self._round_num += 1
        n = len(client_updates)
        if n < self.config.min_clients:
            raise ValueError(
                f"Insufficient clients: {n} < min_clients={self.config.min_clients}. "
                "DP amplification guarantee requires more participants."
            )

        if not client_updates:
            raise ValueError("client_updates is empty")
        dim = len(client_updates[0])

        # Step 1: Clip each update
        clipped, n_clipped = self._clip_updates(client_updates, dim)

        # Step 2: Sum clipped updates
        summed = [sum(clipped[i][j] for i in range(n)) for j in range(dim)]

        # Step 3: Add Gaussian noise (sensitivity = clip_bound)
        sigma  = self.config.noise_multiplier * self.config.clip_bound
        noisy  = [summed[j] + random.gauss(0, sigma) for j in range(dim)]

        # Step 4: Normalise
        normaliser = self.config.fixed_normaliser or n
        aggregate  = [v / normaliser for v in noisy]

        # Per-round epsilon estimate (Gaussian mechanism, simple bound)
        eps_round = self._per_round_epsilon(n)

        result = AggregationResult(
            round_num     = self._round_num,
            n_clients     = n,
            clipped_count = n_clipped,
            noise_added   = True,
            aggregate     = aggregate,
            epsilon_round = eps_round,
        )
        self._log("round_aggregated", round_num=self._round_num,
                  n_clients=n, n_clipped=n_clipped, eps_round=eps_round)
        return result

    def _clip_updates(
        self, updates: List[List[float]], dim: int
    ) -> Tuple[List[List[float]], int]:
        clipped_list = []
        n_clipped    = 0
        S = self.config.clip_bound
        for upd in updates:
            norm = math.sqrt(sum(x * x for x in upd))
            if norm > S:
                scale = S / norm
                clipped_list.append([x * scale for x in upd])
                n_clipped += 1
            else:
                clipped_list.append(list(upd))
        return clipped_list, n_clipped

    def _per_round_epsilon(self, n_clients: int) -> float:
        """Rough per-round (ε, δ)-DP estimate for Gaussian mechanism."""
        sigma = self.config.noise_multiplier
        delta = self.config.target_delta
        if sigma <= 0 or delta <= 0:
            return float("inf")
        try:
            return math.sqrt(2 * math.log(1.25 / delta)) / sigma
        except (ValueError, ZeroDivisionError):
            return float("inf")

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
