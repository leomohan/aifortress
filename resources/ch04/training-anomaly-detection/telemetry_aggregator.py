"""
telemetry_aggregator.py  —  SIEM-ready training anomaly event log
AI Fortress · Chapter 4 · Code Sample 4.B

Collects findings from all training monitors (loss, gradient, LR, checkpoint)
into a unified, structured event log that can be streamed to:
  - Splunk (HTTP Event Collector)
  - Datadog (Event API)
  - CloudWatch Logs
  - Local JSONL file for offline analysis
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional


@dataclass
class TrainingEvent:
    event_id:   str
    timestamp:  str
    job_id:     str
    source:     str      # "loss_spike" | "gradient_norm" | "lr_schedule" | "checkpoint"
    severity:   str      # "info" | "warning" | "critical"
    step:       Optional[int]
    description: str
    details:    dict = field(default_factory=dict)


class TelemetryAggregator:
    """
    Aggregates training anomaly events and writes them to a JSONL event log.

    Parameters
    ----------
    job_id     : Training job identifier
    output_path: Path to output JSONL file (appended to on each event)
    """

    def __init__(self, job_id: str, output_path: Optional[str | Path] = None):
        self.job_id      = job_id
        self.output_path = Path(output_path) if output_path else None
        self._events: List[TrainingEvent] = []

    def record(
        self,
        source:      str,
        severity:    str,
        description: str,
        step:        Optional[int] = None,
        details:     Optional[dict] = None,
    ) -> TrainingEvent:
        event = TrainingEvent(
            event_id    = str(uuid.uuid4()),
            timestamp   = datetime.now(timezone.utc).isoformat(),
            job_id      = self.job_id,
            source      = source,
            severity    = severity,
            step        = step,
            description = description,
            details     = details or {},
        )
        self._events.append(event)
        if self.output_path:
            self._append(event)
        return event

    def ingest_loss_anomaly(self, anomaly: Any) -> TrainingEvent:
        """Ingest a LossAnomaly from LossSpikeDetector."""
        return self.record(
            source      = "loss_spike",
            severity    = anomaly.severity,
            step        = anomaly.step,
            description = anomaly.description,
            details     = {
                "loss":        anomaly.loss,
                "method":      anomaly.method,
                "window_mean": anomaly.window_mean,
                "z_score":     anomaly.z_score,
            },
        )

    def ingest_gradient_anomaly(self, anomaly: Any) -> TrainingEvent:
        """Ingest a GradientAnomaly from GradientNormMonitor."""
        return self.record(
            source      = "gradient_norm",
            severity    = anomaly.severity,
            step        = anomaly.step,
            description = anomaly.description,
            details     = {
                "group_name":    anomaly.group_name,
                "norm":          anomaly.norm,
                "window_mean":   anomaly.window_mean,
                "ratio_to_mean": anomaly.ratio_to_mean,
            },
        )

    def ingest_lr_anomaly(self, anomaly: Any) -> TrainingEvent:
        """Ingest a LRAnomaly from LRScheduleAuditor."""
        return self.record(
            source      = "lr_schedule",
            severity    = anomaly.severity,
            step        = anomaly.step,
            description = anomaly.description,
            details     = {
                "actual_lr":   anomaly.actual_lr,
                "expected_lr": anomaly.expected_lr,
                "deviation":   anomaly.deviation,
            },
        )

    def summary(self) -> dict:
        return {
            "job_id":          self.job_id,
            "total_events":    len(self._events),
            "critical":        sum(1 for e in self._events if e.severity == "critical"),
            "warnings":        sum(1 for e in self._events if e.severity == "warning"),
            "by_source":       {
                src: sum(1 for e in self._events if e.source == src)
                for src in {"loss_spike","gradient_norm","lr_schedule","checkpoint"}
            },
        }

    def save_report(self, path: str | Path) -> None:
        """Save full event log as a JSON report."""
        data = {
            "summary": self.summary(),
            "events":  [asdict(e) for e in self._events],
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _append(self, event: TrainingEvent) -> None:
        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event)) + "\n")
