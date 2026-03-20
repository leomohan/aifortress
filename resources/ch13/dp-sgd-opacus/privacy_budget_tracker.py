"""
privacy_budget_tracker.py  —  Per-model privacy budget register
AI Fortress · Chapter 13 · Code Sample 13.A

Tracks cumulative (ε, δ)-DP budget consumption across multiple
training runs and multiple models. Raises BudgetExhaustedError
when the configured budget is exceeded, preventing silent over-spending.

Design:
  - Each model has its own budget allocation (ε, δ).
  - Budget is spent in increments (one per training step or epoch).
  - Composition is sequential: epsilon adds up across steps.
  - A configurable warn_fraction triggers a WARNING before the budget
    is fully consumed (default 80%).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class BudgetExhaustedError(Exception):
    """Raised when a model's privacy budget is fully consumed."""


@dataclass
class BudgetAllocation:
    model_id:       str
    max_epsilon:    float
    delta:          float
    description:    str = ""
    warn_fraction:  float = 0.80


@dataclass
class BudgetSpending:
    model_id:    str
    step:        int
    epsilon_increment: float
    epsilon_cumulative: float
    delta:       float
    timestamp:   str


@dataclass
class BudgetStatus:
    model_id:           str
    max_epsilon:        float
    epsilon_spent:      float
    epsilon_remaining:  float
    delta:              float
    pct_consumed:       float
    exhausted:          bool
    near_exhausted:     bool   # above warn_fraction
    step_count:         int


class PrivacyBudgetTracker:
    """
    Tracks differential privacy budget across model training runs.

    Parameters
    ----------
    audit_path : Optional JSON Lines path for budget events.
    """

    def __init__(self, audit_path: Optional[str | Path] = None):
        self._allocations: Dict[str, BudgetAllocation] = {}
        self._history:     Dict[str, List[BudgetSpending]] = {}
        self._audit = Path(audit_path) if audit_path else None

    def register(
        self,
        model_id:      str,
        max_epsilon:   float,
        delta:         float,
        description:   str = "",
        warn_fraction: float = 0.80,
    ) -> BudgetAllocation:
        """Register a model with a privacy budget allocation."""
        if max_epsilon <= 0:
            raise ValueError("max_epsilon must be > 0")
        if not (0 < delta < 1):
            raise ValueError("delta must be in (0, 1)")
        alloc = BudgetAllocation(
            model_id=model_id, max_epsilon=max_epsilon, delta=delta,
            description=description, warn_fraction=warn_fraction,
        )
        self._allocations[model_id] = alloc
        self._history[model_id]     = []
        self._log("budget_registered", model_id=model_id,
                  max_epsilon=max_epsilon, delta=delta)
        return alloc

    def spend(
        self,
        model_id:          str,
        epsilon_increment: float,
        raise_on_exceed:   bool = True,
    ) -> BudgetStatus:
        """
        Record epsilon spending for a model.

        Parameters
        ----------
        epsilon_increment : Epsilon consumed in this step.
        raise_on_exceed   : If True, raise BudgetExhaustedError when budget exceeded.
        """
        alloc = self._get_alloc(model_id)
        history = self._history[model_id]
        prev_cumulative = history[-1].epsilon_cumulative if history else 0.0
        cumulative      = prev_cumulative + epsilon_increment

        spending = BudgetSpending(
            model_id           = model_id,
            step               = len(history) + 1,
            epsilon_increment  = epsilon_increment,
            epsilon_cumulative = cumulative,
            delta              = alloc.delta,
            timestamp          = datetime.now(timezone.utc).isoformat(),
        )
        history.append(spending)

        status = self.status(model_id)
        if status.exhausted:
            self._log("budget_exhausted", model_id=model_id,
                      epsilon_spent=cumulative, max_epsilon=alloc.max_epsilon)
            if raise_on_exceed:
                raise BudgetExhaustedError(
                    f"Privacy budget exhausted for '{model_id}': "
                    f"spent ε={cumulative:.4f} > max ε={alloc.max_epsilon}"
                )
        elif status.near_exhausted:
            self._log("budget_warning", model_id=model_id,
                      epsilon_spent=cumulative, max_epsilon=alloc.max_epsilon,
                      pct=round(status.pct_consumed, 1))
        return status

    def status(self, model_id: str) -> BudgetStatus:
        alloc   = self._get_alloc(model_id)
        history = self._history.get(model_id, [])
        spent   = history[-1].epsilon_cumulative if history else 0.0
        pct     = (spent / alloc.max_epsilon) * 100
        return BudgetStatus(
            model_id          = model_id,
            max_epsilon       = alloc.max_epsilon,
            epsilon_spent     = round(spent, 6),
            epsilon_remaining = round(max(0.0, alloc.max_epsilon - spent), 6),
            delta             = alloc.delta,
            pct_consumed      = round(pct, 2),
            exhausted         = spent > alloc.max_epsilon,
            near_exhausted    = pct >= (alloc.warn_fraction * 100),
            step_count        = len(history),
        )

    def all_statuses(self) -> List[BudgetStatus]:
        return [self.status(mid) for mid in self._allocations]

    def reset(self, model_id: str) -> None:
        """Clear spending history for a model (e.g. after re-training from scratch)."""
        self._get_alloc(model_id)
        self._history[model_id] = []
        self._log("budget_reset", model_id=model_id)

    def _get_alloc(self, model_id: str) -> BudgetAllocation:
        alloc = self._allocations.get(model_id)
        if alloc is None:
            raise KeyError(f"Model '{model_id}' not registered. Call register() first.")
        return alloc

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
