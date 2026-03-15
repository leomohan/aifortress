"""
timeline_builder.py  —  Incident timeline builder
AI Fortress · Chapter 17 · Code Sample 17.A

Builds a chronological incident timeline from events, evidence, and
analyst notes. Identifies key milestones (detection, containment,
eradication, recovery) and computes key IR metrics:
  - Time to Detect (TTD)
  - Time to Contain (TTC)
  - Time to Recover (TTR)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


_MILESTONE_TYPES = {
    "incident_start", "detection", "triage_complete", "containment",
    "eradication", "recovery", "postmortem_complete", "closed",
}


@dataclass
class TimelineEvent:
    event_id:    str
    timestamp:   str
    event_type:  str     # milestone type or free-form category
    description: str
    actor:       str     # person or system that performed/observed this
    milestone:   bool    # True if this is a key IR milestone


@dataclass
class IncidentTimeline:
    incident_id:    str
    events:         List[TimelineEvent]
    ttd_minutes:    Optional[float]    # time to detect
    ttc_minutes:    Optional[float]    # time to contain
    ttr_minutes:    Optional[float]    # time to recover
    open_minutes:   Optional[float]    # total incident duration so far

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class IncidentTimelineBuilder:
    """Builds and analyses an incident timeline."""

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self._events: List[TimelineEvent] = []

    def add_event(
        self,
        event_type:  str,
        description: str,
        actor:       str,
        timestamp:   Optional[str] = None,
    ) -> TimelineEvent:
        import uuid
        ts    = timestamp or datetime.now(timezone.utc).isoformat()
        is_ms = event_type in _MILESTONE_TYPES
        ev    = TimelineEvent(
            event_id    = str(uuid.uuid4())[:8],
            timestamp   = ts,
            event_type  = event_type,
            description = description,
            actor       = actor,
            milestone   = is_ms,
        )
        self._events.append(ev)
        # Keep sorted by timestamp
        self._events.sort(key=lambda e: e.timestamp)
        return ev

    def build(self) -> IncidentTimeline:
        milestones = {e.event_type: e for e in self._events if e.milestone}

        def _diff(a_key: str, b_key: str) -> Optional[float]:
            a = milestones.get(a_key)
            b = milestones.get(b_key)
            if not (a and b):
                return None
            try:
                ta = datetime.fromisoformat(a.timestamp.replace("Z", "+00:00"))
                tb = datetime.fromisoformat(b.timestamp.replace("Z", "+00:00"))
                return round(abs((tb - ta).total_seconds() / 60), 2)
            except Exception:
                return None

        start_key  = "incident_start" if "incident_start" in milestones else "detection"
        close_key  = "closed" if "closed" in milestones else "recovery"

        return IncidentTimeline(
            incident_id  = self.incident_id,
            events       = list(self._events),
            ttd_minutes  = _diff("incident_start", "detection"),
            ttc_minutes  = _diff("detection", "containment"),
            ttr_minutes  = _diff("containment", "recovery"),
            open_minutes = _diff(start_key, close_key),
        )
