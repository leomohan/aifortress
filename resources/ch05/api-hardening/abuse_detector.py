"""
abuse_detector.py  —  Model extraction and membership inference detection
AI Fortress · Chapter 5 · Code Sample 5.A

Detects three API abuse patterns from request telemetry:

  1. Model extraction — attacker sends a large volume of queries that
     systematically cover the input space to reconstruct model behaviour.
     Signature: high query volume per key + high input diversity + low label
     repetition in responses.

  2. Membership inference — attacker queries specific inputs (from a
     candidate set) and analyses returned confidence scores to determine
     if those inputs were in the training data.
     Signature: repeated queries for the same input hash across a short window.

  3. DoS / resource exhaustion — high query rate with large input payloads,
     targeting expensive inference paths.
     Signature: sustained high rate + large average payload size.

All detectors are stateless within a time window and designed to be called
after every request in a lightweight async manner.
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set


@dataclass
class AbuseAlert:
    alert_type:   str         # "extraction" | "membership_inference" | "dos"
    severity:     str         # "warning" | "critical"
    key_id:       str
    description:  str
    timestamp:    float
    details:      dict = field(default_factory=dict)


class AbuseDetector:
    """
    Real-time API abuse detector operating on per-request telemetry.

    Parameters
    ----------
    extraction_query_threshold   : Queries per window before extraction alert
    extraction_diversity_ratio   : Min ratio of unique inputs to trigger alert
    mi_repeat_threshold          : Times the same input hash is seen per window
    dos_payload_threshold_kb     : Average payload KB threshold for DoS alert
    window_seconds               : Detection window length
    """

    def __init__(
        self,
        extraction_query_threshold:  int   = 200,
        extraction_diversity_ratio:  float = 0.85,
        mi_repeat_threshold:         int   = 5,
        dos_payload_threshold_kb:    float = 500.0,
        window_seconds:              int   = 300,   # 5-minute window
    ):
        self.extraction_query_threshold  = extraction_query_threshold
        self.extraction_diversity_ratio  = extraction_diversity_ratio
        self.mi_repeat_threshold         = mi_repeat_threshold
        self.dos_payload_threshold_kb    = dos_payload_threshold_kb
        self.window_seconds              = window_seconds

        # Per-key sliding windows
        self._query_times:    Dict[str, Deque[float]] = defaultdict(deque)
        self._input_hashes:   Dict[str, Deque[str]]   = defaultdict(deque)
        self._payload_sizes:  Dict[str, Deque[float]]  = defaultdict(deque)
        self._hash_counts:    Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.alerts:          List[AbuseAlert] = []

    def observe(
        self,
        key_id:       str,
        input_data:   bytes,       # serialised input bytes for hashing
        payload_size_bytes: int,
    ) -> Optional[AbuseAlert]:
        """
        Record a request and return an AbuseAlert if abuse is detected, else None.
        """
        now         = time.monotonic()
        input_hash  = hashlib.sha256(input_data).hexdigest()
        self._cleanup(key_id, now)

        # Record this request
        self._query_times[key_id].append(now)
        self._input_hashes[key_id].append(input_hash)
        self._payload_sizes[key_id].append(payload_size_bytes / 1024.0)  # KB
        self._hash_counts[key_id][input_hash] += 1

        alert: Optional[AbuseAlert] = None

        n_queries = len(self._query_times[key_id])
        hashes    = list(self._input_hashes[key_id])

        # ── Membership inference: repeated identical inputs ────────────────
        repeat_count = self._hash_counts[key_id][input_hash]
        if repeat_count >= self.mi_repeat_threshold:
            alert = AbuseAlert(
                alert_type  = "membership_inference",
                severity    = "critical" if repeat_count >= self.mi_repeat_threshold * 2 else "warning",
                key_id      = key_id,
                description = (
                    f"Key '{key_id}': identical input queried {repeat_count}× in "
                    f"{self.window_seconds}s window — possible membership inference attempt."
                ),
                timestamp   = now,
                details     = {"input_hash": input_hash, "repeat_count": repeat_count},
            )

        # ── Model extraction: high volume + high input diversity ──────────
        elif n_queries >= self.extraction_query_threshold:
            n_unique  = len(set(hashes))
            diversity = n_unique / n_queries if n_queries > 0 else 0.0
            if diversity >= self.extraction_diversity_ratio:
                alert = AbuseAlert(
                    alert_type  = "extraction",
                    severity    = "critical",
                    key_id      = key_id,
                    description = (
                        f"Key '{key_id}': {n_queries} queries with {diversity:.0%} unique inputs "
                        f"in {self.window_seconds}s — possible model extraction attempt."
                    ),
                    timestamp   = now,
                    details     = {
                        "n_queries":        n_queries,
                        "n_unique_inputs":  n_unique,
                        "diversity_ratio":  round(diversity, 4),
                    },
                )

        # ── DoS: high sustained payload volume ───────────────────────────
        if alert is None and len(self._payload_sizes[key_id]) >= 10:
            avg_kb = sum(self._payload_sizes[key_id]) / len(self._payload_sizes[key_id])
            if avg_kb > self.dos_payload_threshold_kb:
                alert = AbuseAlert(
                    alert_type  = "dos",
                    severity    = "warning",
                    key_id      = key_id,
                    description = (
                        f"Key '{key_id}': average payload {avg_kb:.1f} KB over last "
                        f"{len(self._payload_sizes[key_id])} requests — possible DoS."
                    ),
                    timestamp   = now,
                    details     = {"avg_payload_kb": round(avg_kb, 2)},
                )

        if alert:
            self.alerts.append(alert)
        return alert

    def _cleanup(self, key_id: str, now: float) -> None:
        """Evict entries older than the window."""
        cutoff = now - self.window_seconds

        # Clean query times
        q = self._query_times[key_id]
        while q and q[0] < cutoff:
            old_time = q.popleft()

        # Clean input hashes in sync
        h = self._input_hashes[key_id]
        while len(h) > len(self._query_times[key_id]):
            evicted = h.popleft()
            self._hash_counts[key_id][evicted] = max(
                0, self._hash_counts[key_id].get(evicted, 0) - 1
            )

        # Clean payload sizes
        p = self._payload_sizes[key_id]
        while len(p) > len(self._query_times[key_id]):
            p.popleft()

    def summary(self) -> dict:
        return {
            "total_alerts":   len(self.alerts),
            "by_type": {
                t: sum(1 for a in self.alerts if a.alert_type == t)
                for t in ("extraction", "membership_inference", "dos")
            },
            "critical": sum(1 for a in self.alerts if a.severity == "critical"),
        }
