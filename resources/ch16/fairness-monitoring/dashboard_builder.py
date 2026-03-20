"""
dashboard_builder.py  —  Fairness dashboard data builder
AI Fortress · Chapter 16 · Code Sample 16.D

Builds a JSON data structure suitable for rendering a fairness
monitoring dashboard (e.g. in Grafana, Dash, or custom UI).
Aggregates parity history, alert summary, and trend data.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from parity_tracker import ParityTracker
from alert_engine import FairnessAlertEngine


@dataclass
class DashboardData:
    generated_at:      str
    model_name:        str
    n_windows:         int
    latest_dpd:        float
    threshold:         float
    trend_direction:   Optional[str]
    open_alerts:       int
    critical_alerts:   int
    dpd_series:        List[dict]    # [{"window_id": ..., "dpd": ..., "timestamp": ...}]
    group_rate_series: List[dict]    # [{"window_id": ..., "rates": {...}}]
    alerts_summary:    List[dict]

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class DashboardBuilder:
    """Builds dashboard data from a ParityTracker and AlertEngine."""

    def build(
        self,
        model_name: str,
        tracker:    ParityTracker,
        engine:     FairnessAlertEngine,
    ) -> DashboardData:
        history   = tracker.history()
        trend     = tracker.trend()
        alerts    = engine.alerts()
        threshold = history[-1].threshold if history else 0.0
        latest    = history[-1].dpd       if history else 0.0

        dpd_series = [
            {"window_id": o.window_id, "dpd": o.dpd, "timestamp": o.timestamp}
            for o in history
        ]
        rate_series = [
            {"window_id": o.window_id, "rates": o.group_rates, "timestamp": o.timestamp}
            for o in history
        ]
        alerts_sum = [
            {"alert_id": a.alert_id, "severity": a.severity,
             "dpd": a.dpd, "acknowledged": a.acknowledged}
            for a in alerts
        ]

        return DashboardData(
            generated_at     = datetime.now(timezone.utc).isoformat(),
            model_name       = model_name,
            n_windows        = len(history),
            latest_dpd       = latest,
            threshold        = threshold,
            trend_direction  = trend.direction if trend else None,
            open_alerts      = len(engine.open_alerts()),
            critical_alerts  = sum(1 for a in alerts if a.severity == "CRITICAL"),
            dpd_series       = dpd_series,
            group_rate_series = rate_series,
            alerts_summary   = alerts_sum,
        )
