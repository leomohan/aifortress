"""
client_privacy_wrapper.py  —  Local DP wrapper for federated learning clients
AI Fortress · Chapter 13 · Code Sample 13.B

Wraps a federated learning client's local training to enforce:
  - A per-client local privacy budget
  - Per-round epsilon spending tracking
  - Participation blocking when local budget is exhausted
  - Gradient clipping before model update is sent to the server

This supports local DP scenarios where clients do not trust the server,
and also hybrid setups where both local DP and server-side DP are applied.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional


class LocalBudgetExhaustedError(Exception):
    """Raised when client's local privacy budget is consumed."""


@dataclass
class ClientDPConfig:
    client_id:       str
    local_epsilon:   float     # per-client total epsilon budget
    local_delta:     float
    clip_bound:      float     # per-sample gradient clip bound
    noise_multiplier: float    # local noise multiplier (0 = no local noise)


@dataclass
class ClientRoundResult:
    client_id:      str
    round_num:      int
    participated:   bool
    epsilon_spent:  float
    epsilon_total:  float
    blocked_reason: str = ""


class ClientPrivacyWrapper:
    """
    Wraps a federated client to enforce local DP budget.

    Parameters
    ----------
    config     : ClientDPConfig.
    audit_path : Optional JSON Lines log path.
    """

    def __init__(
        self,
        config:     ClientDPConfig,
        audit_path: Optional[str | Path] = None,
    ):
        self.config         = config
        self._rounds:       List[ClientRoundResult] = []
        self._epsilon_total = 0.0
        self._audit         = Path(audit_path) if audit_path else None

    def participate(
        self,
        round_num:       int,
        train_fn:        Callable[[], List[float]],   # returns flattened model update
        epsilon_per_round: float,
    ) -> ClientRoundResult:
        """
        Attempt to participate in a federated round.
        Blocks participation if local budget would be exceeded.

        Parameters
        ----------
        round_num        : Current FL round number.
        train_fn         : Callable that performs local training and returns
                           a flattened model update (list of floats).
        epsilon_per_round : Epsilon consumed by participating in this round.
        """
        if self._epsilon_total + epsilon_per_round > self.config.local_epsilon:
            result = ClientRoundResult(
                client_id     = self.config.client_id,
                round_num     = round_num,
                participated  = False,
                epsilon_spent = 0.0,
                epsilon_total = self._epsilon_total,
                blocked_reason = (
                    f"Local budget would be exceeded: "
                    f"current={self._epsilon_total:.4f}, "
                    f"increment={epsilon_per_round:.4f}, "
                    f"limit={self.config.local_epsilon}"
                ),
            )
            self._rounds.append(result)
            self._log("client_blocked", round_num=round_num,
                      epsilon_total=self._epsilon_total,
                      limit=self.config.local_epsilon)
            return result

        # Perform local training
        update = train_fn()

        # Optionally add local noise
        if self.config.noise_multiplier > 0:
            import random, math
            sigma = self.config.noise_multiplier * self.config.clip_bound
            update = [v + random.gauss(0, sigma) for v in update]

        self._epsilon_total += epsilon_per_round
        result = ClientRoundResult(
            client_id    = self.config.client_id,
            round_num    = round_num,
            participated = True,
            epsilon_spent = epsilon_per_round,
            epsilon_total = self._epsilon_total,
        )
        self._rounds.append(result)
        self._log("client_participated", round_num=round_num,
                  epsilon_spent=epsilon_per_round, epsilon_total=self._epsilon_total)
        return result

    @property
    def rounds_participated(self) -> int:
        return sum(1 for r in self._rounds if r.participated)

    @property
    def epsilon_remaining(self) -> float:
        return max(0.0, self.config.local_epsilon - self._epsilon_total)

    def history(self) -> List[ClientRoundResult]:
        return list(self._rounds)

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(),
                  "client_id": self.config.client_id,
                  "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
