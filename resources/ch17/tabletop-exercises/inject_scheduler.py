"""
inject_scheduler.py  —  Tabletop exercise inject scheduler
AI Fortress · Chapter 17 · Code Sample 17.E

Schedules injects for a real-time tabletop exercise. Returns
injects that are due based on elapsed exercise time.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from scenario_runner import ExerciseSession, Inject


@dataclass
class ScheduledInject:
    inject:       Inject
    due_at_min:   int
    elapsed_min:  float
    overdue:      bool
    delivered:    bool = False


class InjectScheduler:
    """
    Delivers injects based on elapsed exercise time.

    Parameters
    ----------
    session : Active ExerciseSession from ScenarioRunner.
    """

    def __init__(self, session: ExerciseSession):
        self._session   = session
        self._delivered: set = set()

    def due_injects(self) -> List[ScheduledInject]:
        """Return injects due at or before the current elapsed time."""
        start   = datetime.fromisoformat(
            self._session.started_at.replace("Z", "+00:00")
        )
        elapsed = (datetime.now(timezone.utc) - start).total_seconds() / 60
        due     = []
        for inj in self._session.injects:
            if inj.t_plus_min <= elapsed:
                delivered = inj.inject_id in self._delivered
                overdue   = elapsed > inj.t_plus_min + 10   # >10 min past due
                due.append(ScheduledInject(
                    inject      = inj,
                    due_at_min  = inj.t_plus_min,
                    elapsed_min = round(elapsed, 2),
                    overdue     = overdue,
                    delivered   = delivered,
                ))
        return due

    def mark_delivered(self, inject_id: str) -> None:
        self._delivered.add(inject_id)

    def undelivered_due(self) -> List[ScheduledInject]:
        return [s for s in self.due_injects() if not s.delivered]
