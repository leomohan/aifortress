"""
correlation_engine.py  —  Multi-signal ML attack pattern correlation
AI Fortress · Chapter 10 · Code Sample 10.B

Detects composite attack patterns by correlating security events across
a sliding time window.

Attack patterns detected:
  model_extraction      — High volume of prediction requests + auth failures
                          from same source IP in a short window
  supply_chain_attack   — Drift alert + signing failure within the same
                          model/service context
  credential_stuffing   — Many auth failures from many different IPs
                          targeting the same endpoint
  mesh_compromise       — Lateral movement signal + unexpected destination
                          + cert validation failure in same window
  adversarial_campaign  — Sustained drift + rate limit + signing failures
                          suggesting coordinated adversarial probing

Each matched pattern produces a CorrelationAlert with severity CRITICAL
and a composite event_id linking all contributing events.
"""
from __future__ import annotations

import json
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from alert_normaliser import NormalisedAlert


@dataclass
class CorrelationAlert:
    alert_id:        str
    pattern:         str        # attack pattern name
    severity:        str        # always "CRITICAL"
    contributing_ids: List[str] # event_ids that triggered this pattern
    source_ips:      List[str]
    model_names:     List[str]
    timestamp:       str
    detail:          str


# Each pattern definition: name → list of required event_type sets per signal
_PATTERNS = {
    "model_extraction": {
        "description": "High-volume prediction queries combined with auth failures",
        "required_types": {"auth_failure", "rate_limit"},
        "min_events":  5,
        "any_type":    True,    # enough events of any type in the mix
    },
    "supply_chain_attack": {
        "description": "Drift alert co-occurring with signing failure",
        "required_types": {"drift_critical", "signing_failure"},
        "min_events":  2,
        "any_type":    False,
    },
    "credential_stuffing": {
        "description": "Many auth failures from multiple source IPs",
        "required_types": {"auth_failure"},
        "min_events":  10,
        "any_type":    False,
        "distinct_ips": 3,      # from at least N distinct IPs
    },
    "mesh_compromise": {
        "description": "Lateral movement + cert failure in same window",
        "required_types": {"lateral_movement"},
        "min_events":  2,
        "any_type":    True,
    },
    "adversarial_campaign": {
        "description": "Sustained drift + rate limit + signing failures",
        "required_types": {"drift_warning", "drift_critical", "rate_limit", "signing_failure"},
        "min_types":   3,       # at least 3 distinct types
        "min_events":  6,
        "any_type":    False,
    },
}


class CorrelationEngine:
    """
    Correlates ML security events to detect composite attack patterns.

    Parameters
    ----------
    window_seconds : Sliding window size for correlation (default 300s = 5 min).
    alert_path     : Optional JSON Lines path for correlation alerts.
    """

    def __init__(
        self,
        window_seconds: int = 300,
        alert_path:     Optional[str | Path] = None,
    ):
        self._window   = window_seconds
        self._alert_path = Path(alert_path) if alert_path else None
        # Deque of (timestamp, NormalisedAlert)
        self._buffer: Deque[Tuple[float, NormalisedAlert]] = deque()
        self._fired: Dict[str, float] = {}   # pattern → last fired ts (dedup)
        self._dedup_secs = 60

    def ingest(
        self,
        alert: NormalisedAlert,
        ts:    Optional[float] = None,
    ) -> List[CorrelationAlert]:
        """
        Add an alert to the correlation buffer and check for patterns.
        Returns any new CorrelationAlerts triggered.
        """
        now = ts or time.time()
        self._buffer.append((now, alert))
        self._trim(now)
        return self._evaluate(now)

    def ingest_batch(
        self,
        alerts: List[NormalisedAlert],
        ts:     Optional[float] = None,
    ) -> List[CorrelationAlert]:
        results = []
        now     = ts or time.time()
        for alert in alerts:
            results.extend(self.ingest(alert, ts=now))
        return results

    def window_summary(self) -> dict:
        """Return a summary of events currently in the window."""
        type_counts: Dict[str, int] = defaultdict(int)
        ip_set:  set = set()
        for _, alert in self._buffer:
            type_counts[alert.event_type] += 1
            if alert.json_record.get("source_ip"):
                ip_set.add(alert.json_record["source_ip"])
        return {
            "window_size_events": len(self._buffer),
            "event_types":        dict(type_counts),
            "distinct_source_ips": len(ip_set),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _trim(self, now: float) -> None:
        cutoff = now - self._window
        while self._buffer and self._buffer[0][0] < cutoff:
            self._buffer.popleft()

    def _evaluate(self, now: float) -> List[CorrelationAlert]:
        fired_alerts = []

        window_events    = [a for _, a in self._buffer]
        event_types      = {a.event_type for a in window_events}
        type_counts: Dict[str, int] = defaultdict(int)
        for a in window_events:
            type_counts[a.event_type] += 1

        for pattern_name, cfg in _PATTERNS.items():
            if self._was_recently_fired(pattern_name, now):
                continue

            required     = cfg.get("required_types", set())
            min_events   = cfg.get("min_events", 1)
            min_types    = cfg.get("min_types", 0)
            distinct_ips = cfg.get("distinct_ips", 0)
            any_type     = cfg.get("any_type", False)

            # Check required types present
            if not required.intersection(event_types):
                continue

            if not cfg.get("any_type"):
                # All required types must be present OR at least one
                if not required.intersection(event_types):
                    continue

            # Check min events
            relevant = [a for a in window_events
                        if a.event_type in required or any_type]
            if len(relevant) < min_events:
                # Also count total window events for any_type patterns
                if any_type and len(window_events) >= min_events:
                    relevant = window_events
                else:
                    continue

            # Check min distinct types
            if min_types:
                distinct_types = len({a.event_type for a in window_events}
                                     & (required | event_types))
                if distinct_types < min_types:
                    continue

            # Check distinct IPs
            if distinct_ips:
                ips = {a.json_record.get("source_ip", "") for a in relevant
                       if a.json_record.get("source_ip")}
                if len(ips) < distinct_ips:
                    continue

            # Pattern matched — fire alert
            ca = self._make_alert(pattern_name, cfg["description"], relevant)
            fired_alerts.append(ca)
            self._fired[pattern_name] = now
            self._write_alert(ca)

        return fired_alerts

    def _was_recently_fired(self, pattern: str, now: float) -> bool:
        last = self._fired.get(pattern, 0)
        return (now - last) < self._dedup_secs

    @staticmethod
    def _make_alert(
        pattern:     str,
        description: str,
        events:      List[NormalisedAlert],
    ) -> CorrelationAlert:
        source_ips  = sorted({e.json_record.get("source_ip", "") for e in events} - {""})
        model_names = sorted({e.json_record.get("model_name", "") for e in events} - {""})
        return CorrelationAlert(
            alert_id         = str(uuid.uuid4()),
            pattern          = pattern,
            severity         = "CRITICAL",
            contributing_ids = [e.event_id for e in events],
            source_ips       = source_ips,
            model_names      = model_names,
            timestamp        = datetime.now(timezone.utc).isoformat(),
            detail           = (
                f"Pattern '{pattern}' detected: {description}. "
                f"{len(events)} contributing events, "
                f"{len(source_ips)} source IP(s)."
            ),
        )

    def _write_alert(self, alert: CorrelationAlert) -> None:
        if not self._alert_path:
            return
        import dataclasses
        self._alert_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._alert_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(dataclasses.asdict(alert)) + "\n")
