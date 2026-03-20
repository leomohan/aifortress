"""
scenario_runner.py  —  Tabletop exercise scenario runner
AI Fortress · Chapter 17 · Code Sample 17.E

Manages tabletop exercise scenarios for AI security incident response.
A scenario consists of a sequence of injects (timed challenge prompts)
that participants respond to. The runner tracks state, timing, and
participant responses.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class Inject:
    inject_id:    str
    sequence:     int
    title:        str
    description:  str
    t_plus_min:   int       # minutes after exercise start this inject fires
    category:     str       # detection|escalation|containment|communication|recovery
    expected_actions: List[str]   # what good response looks like
    difficulty:   str       # "easy"|"medium"|"hard"


@dataclass
class ParticipantResponse:
    inject_id:    str
    participant:  str
    response_text: str
    responded_at: str
    time_to_respond_min: float


@dataclass
class ExerciseSession:
    session_id:   str
    scenario_name: str
    started_at:   str
    injects:      List[Inject]
    responses:    List[ParticipantResponse] = field(default_factory=list)
    ended_at:     Optional[str] = None
    status:       str = "running"   # "running"|"completed"|"aborted"


class ScenarioRunner:
    """
    Manages tabletop exercise scenarios.

    Parameters
    ----------
    scenario_name : Name of the exercise scenario.
    injects       : Ordered list of Inject objects for the scenario.
    """

    def __init__(self, scenario_name: str, injects: List[Inject]):
        self._name    = scenario_name
        self._injects = sorted(injects, key=lambda i: i.sequence)
        self._session: Optional[ExerciseSession] = None

    def start(self) -> ExerciseSession:
        """Start the exercise session."""
        self._session = ExerciseSession(
            session_id    = str(uuid.uuid4())[:8],
            scenario_name = self._name,
            started_at    = datetime.now(timezone.utc).isoformat(),
            injects       = list(self._injects),
        )
        return self._session

    def record_response(
        self,
        inject_id:     str,
        participant:   str,
        response_text: str,
    ) -> ParticipantResponse:
        if self._session is None:
            raise RuntimeError("Session not started")
        start   = datetime.fromisoformat(
            self._session.started_at.replace("Z", "+00:00")
        )
        now     = datetime.now(timezone.utc)
        elapsed = (now - start).total_seconds() / 60

        resp = ParticipantResponse(
            inject_id           = inject_id,
            participant         = participant,
            response_text       = response_text,
            responded_at        = now.isoformat(),
            time_to_respond_min = round(elapsed, 2),
        )
        self._session.responses.append(resp)
        return resp

    def end(self, status: str = "completed") -> ExerciseSession:
        if self._session is None:
            raise RuntimeError("Session not started")
        self._session.ended_at = datetime.now(timezone.utc).isoformat()
        self._session.status   = status
        return self._session

    def session(self) -> Optional[ExerciseSession]:
        return self._session

    def pending_injects(self) -> List[Inject]:
        """Return injects not yet responded to."""
        if self._session is None:
            return list(self._injects)
        responded_ids = {r.inject_id for r in self._session.responses}
        return [i for i in self._injects if i.inject_id not in responded_ids]
