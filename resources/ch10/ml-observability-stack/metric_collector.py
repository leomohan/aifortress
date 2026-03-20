"""
metric_collector.py  —  Prometheus-format ML metric collector
AI Fortress · Chapter 10 · Code Sample 10.C

Collects ML-specific operational metrics and exposes them in Prometheus
text exposition format for scraping by Prometheus, Grafana, or Datadog.

Metrics tracked:
  ml_requests_total{service, model, status}   — request counter
  ml_latency_ms{service, model, quantile}     — latency histogram (p50/p95/p99)
  ml_error_rate{service, model}               — rolling error rate (last 5 min)
  ml_drift_score{service, model}              — latest drift score (0–100)
  ml_prediction_mean{service, model}          — rolling mean of predictions
  ml_prediction_std{service, model}           — rolling std of predictions
  ml_active_keys{service}                     — number of active API keys
  ml_cert_days_remaining{service, cert_name}  — certificate expiry days

Uses only stdlib — no prometheus_client dependency required.
"""
from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class MetricSample:
    ts:     float
    value:  float


class _RollingWindow:
    """Keeps samples within a sliding time window."""
    def __init__(self, window_secs: int = 300):
        self._window = window_secs
        self._data:  Deque[MetricSample] = deque()

    def add(self, value: float, ts: Optional[float] = None) -> None:
        now = ts or time.time()
        self._data.append(MetricSample(ts=now, value=value))
        self._trim(now)

    def values(self, now: Optional[float] = None) -> List[float]:
        self._trim(now or time.time())
        return [s.value for s in self._data]

    def _trim(self, now: float) -> None:
        cutoff = now - self._window
        while self._data and self._data[0].ts < cutoff:
            self._data.popleft()


def _quantile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = q * (len(s) - 1)
    lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)


class MetricCollector:
    """
    Collects ML operational metrics and exposes Prometheus text format.

    Parameters
    ----------
    service       : Service name label.
    model         : Model name label.
    window_secs   : Rolling window size for rate/latency metrics.
    """

    def __init__(
        self,
        service:     str = "ml-service",
        model:       str = "default",
        window_secs: int = 300,
    ):
        self._service      = service
        self._model        = model
        self._window       = window_secs

        # Counters
        self._requests: Dict[str, int] = defaultdict(int)   # status → count

        # Rolling windows
        self._latencies   = _RollingWindow(window_secs)
        self._predictions = _RollingWindow(window_secs)
        self._errors      = _RollingWindow(window_secs)

        # Gauges
        self._drift_score:      float = 0.0
        self._active_keys:      int   = 0
        self._cert_days:        Dict[str, float] = {}  # cert_name → days

    # ── Record methods ────────────────────────────────────────────────────────

    def record_request(self, status: str = "success", latency_ms: float = 0.0) -> None:
        self._requests[status] += 1
        self._latencies.add(latency_ms)
        self._errors.add(1.0 if status == "error" else 0.0)

    def record_prediction(self, value: float) -> None:
        self._predictions.add(value)

    def set_drift_score(self, score: float) -> None:
        self._drift_score = max(0.0, min(100.0, score))

    def set_active_keys(self, count: int) -> None:
        self._active_keys = count

    def set_cert_expiry(self, cert_name: str, days_remaining: float) -> None:
        self._cert_days[cert_name] = days_remaining

    # ── Prometheus exposition ─────────────────────────────────────────────────

    def expose(self) -> str:
        """Return Prometheus text exposition format string."""
        lines: List[str] = []
        svc   = self._service
        mdl   = self._model
        now   = time.time()

        def label(k: str, v: str) -> str:
            return f'{k}="{v}"'

        def add_gauge(name: str, help_: str, labels: str, value: float) -> None:
            lines.append(f"# HELP {name} {help_}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name}{{{labels}}} {value:.4f}")

        def add_counter(name: str, help_: str, labels: str, value: int) -> None:
            lines.append(f"# HELP {name} {help_}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name}{{{labels}}} {value}")

        # Request counters
        add_counter(
            "ml_requests_total",
            "Total ML inference requests by status",
            f"{label('service', svc)},{label('model', mdl)},{label('status', 'success')}",
            self._requests.get("success", 0),
        )
        add_counter(
            "ml_requests_total",
            "Total ML inference requests by status",
            f"{label('service', svc)},{label('model', mdl)},{label('status', 'error')}",
            self._requests.get("error", 0),
        )

        # Latency quantiles
        lats = self._latencies.values(now)
        lines.append("# HELP ml_latency_ms Inference latency in milliseconds")
        lines.append("# TYPE ml_latency_ms summary")
        for q in (0.50, 0.95, 0.99):
            val = _quantile(lats, q) if lats else 0.0
            lines.append(
                f'ml_latency_ms{{{label("service", svc)},'
                f'{label("model", mdl)},{label("quantile", str(q))}}} {val:.2f}'
            )
        lines.append(
            f'ml_latency_ms_count{{{label("service", svc)},{label("model", mdl)}}} {len(lats)}'
        )

        # Error rate (errors / total in window)
        errs  = self._errors.values(now)
        total = len(errs)
        err_rate = sum(errs) / total if total > 0 else 0.0
        add_gauge(
            "ml_error_rate",
            "Rolling error rate over monitoring window",
            f"{label('service', svc)},{label('model', mdl)}",
            err_rate,
        )

        # Drift score
        add_gauge(
            "ml_drift_score",
            "Latest aggregate drift score 0-100",
            f"{label('service', svc)},{label('model', mdl)}",
            self._drift_score,
        )

        # Prediction distribution
        preds = self._predictions.values(now)
        pred_mean = sum(preds) / len(preds) if preds else 0.0
        pred_var  = (sum((x - pred_mean) ** 2 for x in preds) / len(preds)) if len(preds) > 1 else 0.0
        pred_std  = math.sqrt(pred_var)
        add_gauge(
            "ml_prediction_mean",
            "Rolling mean of model predictions",
            f"{label('service', svc)},{label('model', mdl)}",
            pred_mean,
        )
        add_gauge(
            "ml_prediction_std",
            "Rolling std of model predictions",
            f"{label('service', svc)},{label('model', mdl)}",
            pred_std,
        )

        # Active API keys
        add_gauge(
            "ml_active_keys",
            "Number of active API keys",
            f"{label('service', svc)}",
            float(self._active_keys),
        )

        # Certificate expiry
        for cert_name, days in self._cert_days.items():
            add_gauge(
                "ml_cert_days_remaining",
                "Days until certificate expiry",
                f"{label('service', svc)},{label('cert_name', cert_name)}",
                days,
            )

        return "\n".join(lines) + "\n"

    def snapshot(self) -> dict:
        """Return a dict snapshot of current metrics for JSON logging."""
        now   = time.time()
        lats  = self._latencies.values(now)
        preds = self._predictions.values(now)
        errs  = self._errors.values(now)
        total = len(errs)
        return {
            "service":       self._service,
            "model":         self._model,
            "requests":      dict(self._requests),
            "latency_p50":   round(_quantile(lats, 0.50), 2),
            "latency_p95":   round(_quantile(lats, 0.95), 2),
            "latency_p99":   round(_quantile(lats, 0.99), 2),
            "error_rate":    round(sum(errs) / total if total else 0.0, 4),
            "drift_score":   self._drift_score,
            "prediction_mean": round(sum(preds) / len(preds) if preds else 0.0, 4),
            "active_keys":   self._active_keys,
            "cert_days":     dict(self._cert_days),
        }
