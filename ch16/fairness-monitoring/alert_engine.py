"""
alert_engine.py  —  Fairness alert engine
AI Fortress · Chapter 16 · Code Sample 16.D

Evaluates parity observations against configurable alert policies
and emits structured alerts. Supports three severity tiers:
  WARNING   — DPD approaching threshold (> 80% of threshold)
  ALERT     — DPD exceeds threshold
  CRITICAL  — DPD exceeds 2× threshold OR degrading trend detected
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from parity_tracker import ParityObservation, ParityTrend


@dataclass
class FairnessAlert:
    alert_id:    str
    severity:    str    # "WARNING" | "ALERT" | "CRITICAL"
    window_id:   str
    dpd:         float
    threshold:   float
    group_rates: dict
    trend:       Optional[str]
    message:     str
    timestamp:   str
    acknowledged: bool = False


class FairnessAlertEngine:
    """
    Emits structured fairness alerts from parity observations.

    Parameters
    ----------
    warn_fraction  : Fraction of threshold that triggers a WARNING (default 0.80).
    log_path       : Optional JSON Lines path for alert persistence.
    """

    def __init__(
        self,
        warn_fraction: float = 0.80,
        log_path:      Optional[str | Path] = None,
    ):
        self._warn_frac = warn_fraction
        self._alerts:   List[FairnessAlert] = []
        self._log       = Path(log_path) if log_path else None

    def evaluate(
        self,
        observation: ParityObservation,
        trend:       Optional[ParityTrend] = None,
    ) -> Optional[FairnessAlert]:
        import uuid
        thr  = observation.threshold
        dpd  = observation.dpd
        sev  = None

        if dpd > 2 * thr or (trend and trend.direction == "degrading" and dpd > thr):
            sev = "CRITICAL"
        elif dpd > thr:
            sev = "ALERT"
        elif dpd > thr * self._warn_frac:
            sev = "WARNING"

        if sev is None:
            return None

        trend_str = trend.direction if trend else None
        msg = (
            f"Fairness {sev}: DPD={dpd:.3f} (threshold={thr}). "
            + (f"Trend: {trend_str}." if trend_str else "")
        )
        alert = FairnessAlert(
            alert_id    = str(uuid.uuid4())[:8],
            severity    = sev,
            window_id   = observation.window_id,
            dpd         = dpd,
            threshold   = thr,
            group_rates = observation.group_rates,
            trend       = trend_str,
            message     = msg,
            timestamp   = datetime.now(timezone.utc).isoformat(),
        )
        self._alerts.append(alert)
        if self._log:
            import dataclasses
            with open(self._log, "a") as f:
                f.write(json.dumps(dataclasses.asdict(alert)) + "\n")
        return alert

    def acknowledge(self, alert_id: str) -> None:
        for a in self._alerts:
            if a.alert_id == alert_id:
                a.acknowledged = True
                return
        raise KeyError(f"Alert '{alert_id}' not found")

    def open_alerts(self) -> List[FairnessAlert]:
        return [a for a in self._alerts if not a.acknowledged]

    def alerts(self) -> List[FairnessAlert]:
        return list(self._alerts)
