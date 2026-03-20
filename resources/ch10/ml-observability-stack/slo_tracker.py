"""
slo_tracker.py  —  SLO error budget and burn rate tracking for ML services
AI Fortress · Chapter 10 · Code Sample 10.C

Tracks Service Level Objectives for ML inference endpoints and computes
error-budget consumption and burn rate alerts.

SLO model:
  - Target: e.g. 99.9% availability over a 30-day rolling window
  - Error budget: 100% - target = 0.1% of total requests may fail
  - Burn rate:    actual_error_rate / (1 - target)
    - Burn rate 1× = consuming budget at exactly the allowed pace
    - Burn rate 6× = fast burn → page on-call immediately
    - Burn rate 1–6× = slow burn → alert within 1 hour

Alert tiers:
  CRITICAL (fast burn): burn_rate ≥ 6 (budget exhausted in < 5 days)
  WARNING  (slow burn): burn_rate ≥ 1 (over-consuming budget)
  OK                  : burn_rate < 1

Two windows tracked per SLO (following Google SRE book):
  - Long window:  30 days  (or configurable)
  - Short window: 1 hour   (to catch fast burns early)
"""
from __future__ import annotations

import json
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple


@dataclass
class SLODefinition:
    name:         str
    target:       float     # e.g. 0.999 for 99.9%
    window_days:  int = 30
    service:      str = ""
    description:  str = ""


@dataclass
class BurnRateAlert:
    slo_name:     str
    alert_type:   str    # "fast_burn" | "slow_burn"
    severity:     str    # "CRITICAL" | "WARNING"
    burn_rate:    float
    error_rate:   float
    budget_consumed_pct: float
    window_label: str    # "long" | "short"
    detail:       str


@dataclass
class SLOStatus:
    slo_name:            str
    target:              float
    long_window_error_rate:  float
    short_window_error_rate: float
    long_burn_rate:      float
    short_burn_rate:     float
    budget_consumed_pct: float   # % of 30-day budget consumed
    total_requests_long: int
    total_requests_short: int
    alerts:              List[BurnRateAlert]
    overall:             str     # "OK" | "WARNING" | "CRITICAL"

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class SLOTracker:
    """
    Tracks SLOs for ML endpoints with burn-rate alerting.

    Parameters
    ----------
    slo            : SLODefinition
    fast_burn_thr  : Burn rate threshold for CRITICAL alert (default 6×)
    slow_burn_thr  : Burn rate threshold for WARNING alert (default 1×)
    short_window_secs : Short window size in seconds (default 3600 = 1h)
    """

    def __init__(
        self,
        slo:               SLODefinition,
        fast_burn_thr:     float = 6.0,
        slow_burn_thr:     float = 1.0,
        short_window_secs: int   = 3600,
    ):
        self._slo         = slo
        self._fast        = fast_burn_thr
        self._slow        = slow_burn_thr
        self._short_win   = short_window_secs
        self._long_win    = slo.window_days * 86400

        # (timestamp, is_error) pairs
        self._events: Deque[Tuple[float, bool]] = deque()

    def record(self, is_error: bool, ts: Optional[float] = None) -> None:
        """Record a single request outcome."""
        now = ts or time.time()
        self._events.append((now, is_error))
        self._trim(now)

    def record_batch(
        self,
        total:  int,
        errors: int,
        ts:     Optional[float] = None,
    ) -> None:
        """Record aggregate outcomes for a time window."""
        now = ts or time.time()
        for _ in range(errors):
            self._events.append((now, True))
        for _ in range(total - errors):
            self._events.append((now, False))
        self._trim(now)

    def status(self, now: Optional[float] = None) -> SLOStatus:
        """Compute current SLO status and burn rate alerts."""
        now = now or time.time()
        self._trim(now)

        long_total, long_errors   = self._window_stats(now, self._long_win)
        short_total, short_errors = self._window_stats(now, self._short_win)

        long_err_rate  = long_errors  / long_total  if long_total  > 0 else 0.0
        short_err_rate = short_errors / short_total if short_total > 0 else 0.0

        allowed_rate    = 1.0 - self._slo.target
        long_burn       = long_err_rate  / allowed_rate if allowed_rate > 0 else 0.0
        short_burn      = short_err_rate / allowed_rate if allowed_rate > 0 else 0.0

        # Budget consumed = errors / total_allowed_in_window
        total_allowed = long_total * allowed_rate if long_total > 0 else 1.0
        budget_consumed = min(long_errors / max(total_allowed, 1), 1.0) * 100

        alerts = self._evaluate_alerts(
            long_burn, short_burn, long_err_rate, short_err_rate, budget_consumed
        )

        overall = "OK"
        if any(a.severity == "CRITICAL" for a in alerts):
            overall = "CRITICAL"
        elif any(a.severity == "WARNING" for a in alerts):
            overall = "WARNING"

        return SLOStatus(
            slo_name              = self._slo.name,
            target                = self._slo.target,
            long_window_error_rate  = round(long_err_rate,  6),
            short_window_error_rate = round(short_err_rate, 6),
            long_burn_rate          = round(long_burn,  2),
            short_burn_rate         = round(short_burn, 2),
            budget_consumed_pct     = round(budget_consumed, 2),
            total_requests_long     = long_total,
            total_requests_short    = short_total,
            alerts                  = alerts,
            overall                 = overall,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _trim(self, now: float) -> None:
        cutoff = now - self._long_win
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def _window_stats(self, now: float, window: int) -> Tuple[int, int]:
        cutoff = now - window
        total = errors = 0
        for ts, is_err in self._events:
            if ts >= cutoff:
                total += 1
                if is_err:
                    errors += 1
        return total, errors

    def _evaluate_alerts(
        self,
        long_burn:     float,
        short_burn:    float,
        long_rate:     float,
        short_rate:    float,
        budget_pct:    float,
    ) -> List[BurnRateAlert]:
        alerts = []
        allowed = 1.0 - self._slo.target

        if short_burn >= self._fast:
            alerts.append(BurnRateAlert(
                slo_name     = self._slo.name,
                alert_type   = "fast_burn",
                severity     = "CRITICAL",
                burn_rate    = round(short_burn, 2),
                error_rate   = round(short_rate, 6),
                budget_consumed_pct = round(budget_pct, 2),
                window_label = "short",
                detail       = (
                    f"Fast burn detected: {short_burn:.1f}× budget consumption "
                    f"in short window. Error rate={short_rate:.4%} "
                    f"(allowed={allowed:.4%})."
                ),
            ))
        elif long_burn >= self._fast:
            alerts.append(BurnRateAlert(
                slo_name     = self._slo.name,
                alert_type   = "fast_burn",
                severity     = "CRITICAL",
                burn_rate    = round(long_burn, 2),
                error_rate   = round(long_rate, 6),
                budget_consumed_pct = round(budget_pct, 2),
                window_label = "long",
                detail       = (
                    f"Fast burn in long window: {long_burn:.1f}× budget consumption."
                ),
            ))
        elif long_burn >= self._slow:
            alerts.append(BurnRateAlert(
                slo_name     = self._slo.name,
                alert_type   = "slow_burn",
                severity     = "WARNING",
                burn_rate    = round(long_burn, 2),
                error_rate   = round(long_rate, 6),
                budget_consumed_pct = round(budget_pct, 2),
                window_label = "long",
                detail       = (
                    f"Slow burn: consuming error budget at {long_burn:.1f}× "
                    f"the allowed rate. Error rate={long_rate:.4%}."
                ),
            ))
        return alerts
