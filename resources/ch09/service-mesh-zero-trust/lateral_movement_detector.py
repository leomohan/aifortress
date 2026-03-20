"""
lateral_movement_detector.py  —  East-west lateral movement detection
AI Fortress · Chapter 9 · Code Sample 9.B

Detects anomalous inter-service traffic patterns that may indicate a
compromised ML microservice attempting lateral movement.

Detection signals:
  1. Fan-out explosion  — service suddenly calling far more peers than baseline
  2. High-value target  — first-time connection to a designated sensitive service
                         (model registry, training data store, secret manager)
  3. High-frequency probe — unusually high call rate to a single destination
                            (scanning / credential brute-force pattern)
  4. Unexpected destination — service calling a peer it has never called before
                               and that is not in its approved peer list

Each event is scored with a severity and written to a structured alert log.
The detector maintains a sliding-window call history per source workload.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple


@dataclass
class LateralMovementAlert:
    alert_id:    str
    timestamp:   str
    signal:      str     # "fan_out" | "high_value_target" | "high_freq_probe" | "unexpected_dest"
    severity:    str     # "HIGH" | "CRITICAL"
    source:      str
    destination: str
    detail:      str


class LateralMovementDetector:
    """
    Detects lateral movement patterns in ML service mesh traffic.

    Parameters
    ----------
    approved_peers      : Dict of {source_spiffe_id: {allowed_destination_names}}.
                          Sources not in this dict are assumed to have no approved peers.
    high_value_services : Set of service names considered high-value targets
                          (model registry, feature store, secret manager, etc.).
    fan_out_threshold   : Alert when a source calls more than this many unique
                          destinations within the observation window.
    probe_threshold     : Alert when call frequency to a single destination exceeds
                          this rate (calls per minute).
    window_seconds      : Sliding window size for frequency calculations (default 60s).
    alert_path          : Optional path for JSON Lines alert log.
    """

    def __init__(
        self,
        approved_peers:      Optional[Dict[str, Set[str]]] = None,
        high_value_services: Optional[Set[str]] = None,
        fan_out_threshold:   int = 10,
        probe_threshold:     int = 100,   # calls/minute to single dest
        window_seconds:      int = 60,
        alert_path:          Optional[str | Path] = None,
    ):
        self._approved        = approved_peers or {}
        self._high_value      = high_value_services or set()
        self._fan_out_thresh  = fan_out_threshold
        self._probe_thresh    = probe_threshold
        self._window          = window_seconds
        self._alert_path      = Path(alert_path) if alert_path else None

        # State: source → deque of (timestamp, destination) tuples
        self._call_history: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        # State: source → set of destinations ever seen
        self._seen_dests: Dict[str, Set[str]] = defaultdict(set)

        self._alert_counter = 0

    def observe(
        self,
        source:      str,
        destination: str,
        ts:          Optional[float] = None,
    ) -> List[LateralMovementAlert]:
        """
        Record a service call and check for lateral movement signals.
        Returns a (possibly empty) list of alerts triggered by this call.
        """
        now      = ts or time.time()
        history  = self._call_history[source]
        alerts:  List[LateralMovementAlert] = []

        # Trim old entries outside the window
        cutoff = now - self._window
        while history and history[0][0] < cutoff:
            history.popleft()

        history.append((now, destination))

        # Signal 1: Unexpected destination
        approved = self._approved.get(source)
        if approved is not None and destination not in approved:
            alerts.append(self._alert(
                signal      = "unexpected_dest",
                severity    = "HIGH",
                source      = source,
                destination = destination,
                detail      = f"'{source}' called '{destination}' which is not in its "
                              f"approved peer list {sorted(approved)}",
            ))

        # Signal 2: High-value target — first-time connection
        if destination in self._high_value and destination not in self._seen_dests[source]:
            alerts.append(self._alert(
                signal      = "high_value_target",
                severity    = "CRITICAL",
                source      = source,
                destination = destination,
                detail      = f"First-ever connection from '{source}' to high-value "
                              f"service '{destination}'",
            ))

        self._seen_dests[source].add(destination)

        # Signal 3: Fan-out explosion — too many unique destinations in window
        unique_dests = {d for _, d in history}
        if len(unique_dests) > self._fan_out_thresh:
            alerts.append(self._alert(
                signal      = "fan_out",
                severity    = "HIGH",
                source      = source,
                destination = destination,
                detail      = f"'{source}' called {len(unique_dests)} unique destinations "
                              f"in {self._window}s (threshold={self._fan_out_thresh})",
            ))

        # Signal 4: High-frequency probe — many calls to same destination in window
        dest_calls = sum(1 for _, d in history if d == destination)
        rate_per_min = dest_calls * (60.0 / self._window)
        if rate_per_min > self._probe_thresh:
            alerts.append(self._alert(
                signal      = "high_freq_probe",
                severity    = "HIGH",
                source      = source,
                destination = destination,
                detail      = f"'{source}' → '{destination}': {dest_calls} calls in "
                              f"{self._window}s ({rate_per_min:.0f}/min, "
                              f"threshold={self._probe_thresh}/min)",
            ))

        for alert in alerts:
            self._write_alert(alert)

        return alerts

    def get_call_stats(self, source: str) -> dict:
        """Return current call statistics for a source workload."""
        history     = self._call_history[source]
        unique_dests = {d for _, d in history}
        return {
            "source":       source,
            "calls_in_window": len(history),
            "unique_destinations": len(unique_dests),
            "destinations":  sorted(unique_dests),
            "seen_ever":     sorted(self._seen_dests[source]),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _alert(self, signal: str, severity: str, source: str,
               destination: str, detail: str) -> LateralMovementAlert:
        import uuid
        self._alert_counter += 1
        return LateralMovementAlert(
            alert_id    = str(uuid.uuid4()),
            timestamp   = datetime.now(timezone.utc).isoformat(),
            signal      = signal,
            severity    = severity,
            source      = source,
            destination = destination,
            detail      = detail,
        )

    def _write_alert(self, alert: LateralMovementAlert) -> None:
        if self._alert_path is None:
            return
        import dataclasses
        self._alert_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._alert_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(dataclasses.asdict(alert)) + "\n")
