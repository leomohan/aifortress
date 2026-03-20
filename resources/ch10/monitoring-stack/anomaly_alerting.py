"""
anomaly_alerting.py  —  Threshold and statistical anomaly alerting rules
AI Fortress · Chapter 10 · Code Sample 10.C

Evaluates alerting rules against collected ML metrics and emits structured
alerts for SIEM ingestion.

Rule types:
  ThresholdRule     — alert when metric exceeds a fixed threshold
  RateOfChangeRule  — alert when metric changes by more than X% per interval
  AnomalyRule       — alert when metric deviates > N standard deviations
                      from its rolling mean (z-score)
  CompositeRule     — alert when multiple child rules fire simultaneously

Alert severity mapping:
  CRITICAL : requires immediate response
  WARNING  : investigate within 1 hour
  INFO     : monitor — may indicate early-stage drift
"""
from __future__ import annotations

import json
import math
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class MetricPoint:
    ts:     float
    name:   str
    value:  float
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class AlertFiring:
    alert_id:   str
    rule_name:  str
    severity:   str
    metric:     str
    value:      float
    threshold:  float
    timestamp:  str
    detail:     str
    labels:     Dict[str, str] = field(default_factory=dict)


# ── Rule base class ───────────────────────────────────────────────────────────

class AlertRule(ABC):
    def __init__(self, name: str, metric: str, severity: str = "WARNING"):
        self.name     = name
        self.metric   = metric
        self.severity = severity

    @abstractmethod
    def evaluate(self, point: MetricPoint) -> Optional[AlertFiring]:
        ...


# ── Rule types ────────────────────────────────────────────────────────────────

class ThresholdRule(AlertRule):
    """
    Alert when metric value crosses a threshold.

    Parameters
    ----------
    threshold : Numeric threshold.
    direction : "above" (alert if value > threshold) or "below".
    """

    def __init__(
        self,
        name:      str,
        metric:    str,
        threshold: float,
        direction: str    = "above",
        severity:  str    = "WARNING",
    ):
        super().__init__(name, metric, severity)
        self._threshold = threshold
        self._above     = direction == "above"

    def evaluate(self, point: MetricPoint) -> Optional[AlertFiring]:
        if point.name != self.metric:
            return None
        triggered = (point.value > self._threshold) if self._above \
                    else (point.value < self._threshold)
        if not triggered:
            return None
        direction = "above" if self._above else "below"
        return AlertFiring(
            alert_id  = str(uuid.uuid4()),
            rule_name = self.name,
            severity  = self.severity,
            metric    = self.metric,
            value     = round(point.value, 4),
            threshold = self._threshold,
            timestamp = datetime.now(timezone.utc).isoformat(),
            detail    = (f"{self.metric}={point.value:.4f} is {direction} "
                         f"threshold {self._threshold}"),
            labels    = point.labels,
        )


class RateOfChangeRule(AlertRule):
    """
    Alert when a metric changes by more than `pct_change` percent
    relative to the previous observed value.
    """

    def __init__(
        self,
        name:       str,
        metric:     str,
        pct_change: float = 50.0,
        severity:   str   = "WARNING",
    ):
        super().__init__(name, metric, severity)
        self._threshold = pct_change
        self._prev:      Optional[float] = None

    def evaluate(self, point: MetricPoint) -> Optional[AlertFiring]:
        if point.name != self.metric:
            return None
        if self._prev is None:
            self._prev = point.value
            return None
        if self._prev == 0:
            self._prev = point.value
            return None
        change_pct = abs(point.value - self._prev) / abs(self._prev) * 100
        prev_val   = self._prev
        self._prev = point.value
        if change_pct < self._threshold:
            return None
        return AlertFiring(
            alert_id  = str(uuid.uuid4()),
            rule_name = self.name,
            severity  = self.severity,
            metric    = self.metric,
            value     = round(point.value, 4),
            threshold = self._threshold,
            timestamp = datetime.now(timezone.utc).isoformat(),
            detail    = (f"{self.metric} changed by {change_pct:.1f}% "
                         f"(prev={prev_val:.4f}, now={point.value:.4f})"),
            labels    = point.labels,
        )


class AnomalyRule(AlertRule):
    """
    Alert when a metric deviates > `z_threshold` standard deviations
    from its rolling mean (z-score anomaly detection).

    Parameters
    ----------
    window_size  : Number of recent points to use for mean/std calculation.
    z_threshold  : Z-score above which an alert fires.
    min_samples  : Minimum samples needed before alerting.
    """

    def __init__(
        self,
        name:        str,
        metric:      str,
        z_threshold: float = 3.0,
        window_size: int   = 50,
        min_samples: int   = 10,
        severity:    str   = "WARNING",
    ):
        super().__init__(name, metric, severity)
        self._z_thr     = z_threshold
        self._window    = deque(maxlen=window_size)
        self._min       = min_samples

    def evaluate(self, point: MetricPoint) -> Optional[AlertFiring]:
        if point.name != self.metric:
            return None

        # Add to window BEFORE checking (so current point isn't included in baseline)
        if len(self._window) >= self._min:
            vals = list(self._window)
            mean = sum(vals) / len(vals)
            var  = sum((v - mean) ** 2 for v in vals) / len(vals)
            std  = math.sqrt(var)
            if std > 0:
                z = abs(point.value - mean) / std
                self._window.append(point.value)
                if z > self._z_thr:
                    return AlertFiring(
                        alert_id  = str(uuid.uuid4()),
                        rule_name = self.name,
                        severity  = self.severity,
                        metric    = self.metric,
                        value     = round(point.value, 4),
                        threshold = self._z_thr,
                        timestamp = datetime.now(timezone.utc).isoformat(),
                        detail    = (f"{self.metric} z-score={z:.2f} "
                                     f"(threshold={self._z_thr}, "
                                     f"mean={mean:.4f}, std={std:.4f})"),
                        labels    = point.labels,
                    )
                return None

        self._window.append(point.value)
        return None


class CompositeRule(AlertRule):
    """
    Alert when ALL child rules fire on the same metric point.
    Useful for requiring multiple conditions before escalating.
    """

    def __init__(
        self,
        name:     str,
        rules:    List[AlertRule],
        severity: str = "CRITICAL",
    ):
        super().__init__(name, metric="*", severity=severity)
        self._rules = rules

    def evaluate(self, point: MetricPoint) -> Optional[AlertFiring]:
        firings = [r.evaluate(point) for r in self._rules]
        if all(f is not None for f in firings):
            details = "; ".join(f.detail for f in firings if f)
            return AlertFiring(
                alert_id  = str(uuid.uuid4()),
                rule_name = self.name,
                severity  = self.severity,
                metric    = point.name,
                value     = point.value,
                threshold = 0.0,
                timestamp = datetime.now(timezone.utc).isoformat(),
                detail    = f"Composite rule fired: {details}",
                labels    = point.labels,
            )
        return None


# ── Alert evaluator ───────────────────────────────────────────────────────────

class AlertEvaluator:
    """
    Evaluates a set of alert rules against incoming metric points.

    Parameters
    ----------
    rules      : List of AlertRule instances.
    alert_path : Optional JSON Lines path for fired alerts.
    """

    def __init__(
        self,
        rules:      List[AlertRule],
        alert_path: Optional[str | Path] = None,
    ):
        self._rules     = rules
        self._alert_path = Path(alert_path) if alert_path else None
        self._history:  List[AlertFiring] = []

    def evaluate(self, point: MetricPoint) -> List[AlertFiring]:
        """Evaluate all rules against a single metric point."""
        fired = []
        for rule in self._rules:
            try:
                result = rule.evaluate(point)
                if result:
                    fired.append(result)
                    self._history.append(result)
                    self._write(result)
            except Exception:
                pass
        return fired

    def evaluate_snapshot(self, snapshot: Dict[str, float],
                          labels: Optional[Dict[str, str]] = None) -> List[AlertFiring]:
        """Evaluate all rules from a metric snapshot dict."""
        now   = time.time()
        fired = []
        for metric_name, value in snapshot.items():
            point = MetricPoint(ts=now, name=metric_name,
                                value=value, labels=labels or {})
            fired.extend(self.evaluate(point))
        return fired

    def fired_alerts(self) -> List[AlertFiring]:
        return list(self._history)

    def _write(self, alert: AlertFiring) -> None:
        if not self._alert_path:
            return
        import dataclasses
        self._alert_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._alert_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(dataclasses.asdict(alert)) + "\n")
