"""
parity_tracker.py  —  Production fairness parity tracker
AI Fortress · Chapter 16 · Code Sample 16.D

Monitors demographic parity difference over rolling time windows
in production. Detects fairness drift (parity worsening over time)
and raises alerts when thresholds are breached.

Each call to record() adds a new observation window. The tracker
maintains a sliding history and computes trend direction.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ParityObservation:
    window_id:      str
    timestamp:      str
    n_samples:      int
    group_rates:    Dict[str, float]   # group → positive rate
    dpd:            float              # max parity difference across groups
    threshold:      float
    breached:       bool


@dataclass
class ParityTrend:
    direction:      str    # "improving" | "stable" | "degrading"
    dpd_delta:      float  # change from first to last observation
    n_observations: int
    first_dpd:      float
    last_dpd:       float


class ParityTracker:
    """
    Tracks demographic parity difference over time in production.

    Parameters
    ----------
    dpd_threshold : Alert threshold for parity difference.
    window_size   : Minimum samples per observation window.
    history_path  : Optional JSON Lines path for persistence.
    """

    def __init__(
        self,
        dpd_threshold: float = 0.10,
        window_size:   int   = 100,
        history_path:  Optional[str | Path] = None,
    ):
        self._threshold    = dpd_threshold
        self._window_size  = window_size
        self._history:     List[ParityObservation] = []
        self._path         = Path(history_path) if history_path else None

    def record(
        self,
        y_pred:  List[int],
        groups:  List[str],
        window_id: Optional[str] = None,
    ) -> ParityObservation:
        """Record a new observation window."""
        import uuid
        if len(y_pred) != len(groups):
            raise ValueError("y_pred and groups must have the same length")
        if len(y_pred) < self._window_size:
            raise ValueError(
                f"Window has {len(y_pred)} samples; min is {self._window_size}"
            )

        # Compute per-group positive rates
        group_data: Dict[str, List[int]] = {}
        for pred, g in zip(y_pred, groups):
            group_data.setdefault(g, []).append(pred)
        rates = {g: sum(preds) / len(preds) for g, preds in group_data.items()}
        dpd   = max(rates.values()) - min(rates.values()) if len(rates) > 1 else 0.0

        obs = ParityObservation(
            window_id   = window_id or str(uuid.uuid4())[:8],
            timestamp   = datetime.now(timezone.utc).isoformat(),
            n_samples   = len(y_pred),
            group_rates = {g: round(r, 4) for g, r in rates.items()},
            dpd         = round(dpd, 4),
            threshold   = self._threshold,
            breached    = dpd > self._threshold,
        )
        self._history.append(obs)
        if self._path:
            with open(self._path, "a") as f:
                import dataclasses
                f.write(json.dumps(dataclasses.asdict(obs)) + "\n")
        return obs

    def trend(self) -> Optional[ParityTrend]:
        if len(self._history) < 2:
            return None
        first = self._history[0].dpd
        last  = self._history[-1].dpd
        delta = last - first
        direction = (
            "degrading"  if delta >  0.02 else
            "improving"  if delta < -0.02 else
            "stable"
        )
        return ParityTrend(
            direction=direction, dpd_delta=round(delta, 4),
            n_observations=len(self._history),
            first_dpd=first, last_dpd=last,
        )

    def breached_windows(self) -> List[ParityObservation]:
        return [o for o in self._history if o.breached]

    def history(self) -> List[ParityObservation]:
        return list(self._history)
