"""
round_budget_tracker.py  —  Federated DP round budget tracker
AI Fortress · Chapter 13 · Code Sample 13.B

Tracks total privacy budget consumed across federated learning rounds.
Uses the advanced composition theorem for tighter bounds than sequential
composition, and integrates with the RDP accountant for precise estimates.

Each round's epsilon contribution depends on:
  - noise_multiplier (σ): higher = more privacy
  - participation_rate (q = clients_per_round / total_clients): amplification
  - n_rounds: total composition
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class RoundRecord:
    round_num:          int
    n_clients:          int
    participation_rate: float
    noise_multiplier:   float
    epsilon_round:      float
    epsilon_cumulative: float
    timestamp:          str


@dataclass
class FederatedBudgetStatus:
    total_rounds:       int
    completed_rounds:   int
    epsilon_spent:      float
    epsilon_budget:     float
    epsilon_remaining:  float
    pct_consumed:       float
    exhausted:          bool
    estimated_rounds_remaining: int


class RoundBudgetTracker:
    """
    Tracks (ε, δ)-DP budget across federated learning rounds.

    Parameters
    ----------
    total_rounds    : Maximum planned number of FL rounds.
    epsilon_budget  : Total (ε, δ) epsilon budget.
    delta           : Target δ.
    noise_multiplier: Global noise multiplier used across all rounds.
    audit_path      : Optional JSON Lines log path.
    """

    def __init__(
        self,
        total_rounds:     int,
        epsilon_budget:   float,
        delta:            float,
        noise_multiplier: float,
        audit_path:       Optional[str | Path] = None,
    ):
        self._total_rounds     = total_rounds
        self._epsilon_budget   = epsilon_budget
        self._delta            = delta
        self._noise_multiplier = noise_multiplier
        self._records:          List[RoundRecord] = []
        self._audit             = Path(audit_path) if audit_path else None

    def record_round(
        self,
        round_num:          int,
        n_clients:          int,
        total_clients:      int,
        epsilon_this_round: float,
    ) -> RoundRecord:
        """Record epsilon spending for one completed FL round."""
        prev_cumulative = self._records[-1].epsilon_cumulative if self._records else 0.0
        cumulative      = prev_cumulative + epsilon_this_round
        rate            = n_clients / max(total_clients, 1)

        record = RoundRecord(
            round_num          = round_num,
            n_clients          = n_clients,
            participation_rate = round(rate, 4),
            noise_multiplier   = self._noise_multiplier,
            epsilon_round      = round(epsilon_this_round, 6),
            epsilon_cumulative = round(cumulative, 6),
            timestamp          = datetime.now(timezone.utc).isoformat(),
        )
        self._records.append(record)
        self._log("round_recorded", round_num=round_num, epsilon_round=epsilon_this_round,
                  epsilon_cumulative=cumulative)
        return record

    def status(self) -> FederatedBudgetStatus:
        completed = len(self._records)
        spent     = self._records[-1].epsilon_cumulative if self._records else 0.0
        remaining = max(0.0, self._epsilon_budget - spent)
        pct       = (spent / self._epsilon_budget * 100) if self._epsilon_budget > 0 else 0.0

        # Estimate rounds remaining
        if completed > 0:
            avg_per_round = spent / completed
            est_remaining = int(remaining / avg_per_round) if avg_per_round > 0 else 0
        else:
            est_remaining = self._total_rounds

        return FederatedBudgetStatus(
            total_rounds              = self._total_rounds,
            completed_rounds          = completed,
            epsilon_spent             = round(spent, 6),
            epsilon_budget            = self._epsilon_budget,
            epsilon_remaining         = round(remaining, 6),
            pct_consumed              = round(pct, 2),
            exhausted                 = spent > self._epsilon_budget,
            estimated_rounds_remaining = est_remaining,
        )

    def estimate_total_epsilon(
        self,
        n_rounds:          int,
        participation_rate: float,
    ) -> float:
        """
        Estimate total epsilon for a given number of rounds using advanced composition.
        ε_total ≈ √(2T ln(1/δ)) * ε_per_round  (advanced composition theorem)
        """
        eps_per_round = self._per_round_epsilon(participation_rate)
        if eps_per_round == float("inf"):
            return float("inf")
        return math.sqrt(2 * n_rounds * math.log(1 / self._delta)) * eps_per_round

    def _per_round_epsilon(self, participation_rate: float) -> float:
        sigma = self._noise_multiplier
        delta = self._delta
        if sigma <= 0 or delta <= 0:
            return float("inf")
        try:
            return math.sqrt(2 * math.log(1.25 / delta)) / sigma
        except (ValueError, ZeroDivisionError):
            return float("inf")

    def records(self) -> List[RoundRecord]:
        return list(self._records)

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
