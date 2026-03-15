"""
deadline_tracker.py  —  Regulatory notification deadline tracker
AI Fortress · Chapter 17 · Code Sample 17.B

Tracks notification deadlines from incident discovery timestamp.
Raises warnings at 50% and 80% of each deadline window.
Marks obligations as overdue when deadline passes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class DeadlineStatus:
    regulation:       str
    deadline_at:      Optional[str]   # ISO timestamp; None = manual deadline
    deadline_label:   str
    hours_remaining:  Optional[float]
    percent_elapsed:  Optional[float]
    status:           str             # "on_track"|"warning"|"urgent"|"overdue"|"manual"
    submitted:        bool = False


@dataclass
class DeadlineDashboard:
    incident_id:      str
    discovery_at:     str
    checked_at:       str
    statuses:         List[DeadlineStatus]
    overdue:          List[str]
    urgent:           List[str]       # >80% elapsed


class DeadlineTracker:
    """
    Tracks regulatory notification deadlines for an incident.

    Parameters
    ----------
    incident_id   : Incident identifier.
    discovery_at  : ISO 8601 timestamp when incident was discovered.
    """

    def __init__(self, incident_id: str, discovery_at: str):
        self._incident    = incident_id
        self._discovery   = datetime.fromisoformat(
            discovery_at.replace("Z", "+00:00")
        )
        self._deadlines:  List[dict] = []

    def add(
        self,
        regulation:     str,
        deadline_hours: Optional[int],
        deadline_label: str,
    ) -> None:
        self._deadlines.append({
            "regulation":     regulation,
            "deadline_hours": deadline_hours,
            "deadline_label": deadline_label,
            "submitted":      False,
        })

    def mark_submitted(self, regulation: str) -> None:
        for d in self._deadlines:
            if d["regulation"] == regulation:
                d["submitted"] = True
                return
        raise KeyError(f"Regulation '{regulation}' not tracked")

    def status(self) -> DeadlineDashboard:
        now      = datetime.now(timezone.utc)
        statuses: List[DeadlineStatus] = []
        overdue:  List[str] = []
        urgent:   List[str] = []

        for d in self._deadlines:
            if d["submitted"]:
                statuses.append(DeadlineStatus(
                    regulation=d["regulation"], deadline_at=None,
                    deadline_label=d["deadline_label"], hours_remaining=None,
                    percent_elapsed=None, status="submitted", submitted=True,
                ))
                continue

            hours = d["deadline_hours"]
            if hours is None:
                statuses.append(DeadlineStatus(
                    regulation=d["regulation"], deadline_at=None,
                    deadline_label=d["deadline_label"], hours_remaining=None,
                    percent_elapsed=None, status="manual",
                ))
                continue

            deadline_dt   = self._discovery + timedelta(hours=hours)
            hrs_remaining = (deadline_dt - now).total_seconds() / 3600
            pct_elapsed   = max(0.0, min(100.0, (1 - hrs_remaining / hours) * 100))

            if hrs_remaining <= 0:
                st = "overdue"
                overdue.append(d["regulation"])
            elif pct_elapsed >= 80:
                st = "urgent"
                urgent.append(d["regulation"])
            elif pct_elapsed >= 50:
                st = "warning"
            else:
                st = "on_track"

            statuses.append(DeadlineStatus(
                regulation      = d["regulation"],
                deadline_at     = deadline_dt.isoformat(),
                deadline_label  = d["deadline_label"],
                hours_remaining = round(hrs_remaining, 2),
                percent_elapsed = round(pct_elapsed, 1),
                status          = st,
            ))

        return DeadlineDashboard(
            incident_id  = self._incident,
            discovery_at = self._discovery.isoformat(),
            checked_at   = now.isoformat(),
            statuses     = statuses,
            overdue      = overdue,
            urgent       = urgent,
        )
