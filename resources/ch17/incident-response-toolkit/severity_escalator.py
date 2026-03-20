"""
severity_escalator.py  —  Dynamic severity escalation engine
AI Fortress · Chapter 17 · Code Sample 17.A

Re-evaluates incident severity as new evidence arrives.
Severity can only be escalated (never de-escalated during active
response — downgrade requires explicit commander sign-off).

Escalation triggers:
  - Privacy impact confirmed → minimum P2
  - Exfiltration confirmed   → minimum P1
  - High-risk AI system affected → minimum P2
  - >100 individuals affected → minimum P2
  - >10,000 individuals affected → minimum P1
  - Active attack in progress → P1
  - Regulatory obligation triggered → minimum P2
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


_SEVERITY_RANK = {"P4": 4, "P3": 3, "P2": 2, "P1": 1}
_RANK_SEVERITY = {v: k for k, v in _SEVERITY_RANK.items()}


@dataclass
class EscalationEvent:
    trigger:         str
    old_severity:    str
    new_severity:    str
    escalated_by:    str
    timestamp:       str
    rationale:       str


@dataclass
class EscalationResult:
    incident_id:       str
    current_severity:  str
    escalation_history: List[EscalationEvent]
    escalated:         bool


class SeverityEscalator:
    """
    Dynamically escalates incident severity based on new findings.

    Parameters
    ----------
    incident_id       : Incident being tracked.
    initial_severity  : Starting severity (P1–P4).
    """

    def __init__(self, incident_id: str, initial_severity: str = "P4"):
        if initial_severity not in _SEVERITY_RANK:
            raise ValueError(f"severity must be one of {list(_SEVERITY_RANK)}")
        self._id       = incident_id
        self._severity = initial_severity
        self._history: List[EscalationEvent] = []

    @property
    def current_severity(self) -> str:
        return self._severity

    def evaluate(
        self,
        affected_individuals: int = 0,
        privacy_impact:       bool = False,
        exfiltration:         bool = False,
        high_risk_ai:         bool = False,
        active_attack:        bool = False,
        regulatory_triggered: bool = False,
        escalated_by:         str  = "ir-system",
    ) -> EscalationResult:
        """
        Evaluate new evidence and escalate if warranted.
        Severity can only increase during active response.
        """
        required_rank = _SEVERITY_RANK[self._severity]   # lower rank = higher severity

        triggers = []
        if active_attack:
            required_rank = min(required_rank, 1)   # P1
            triggers.append("active_attack_in_progress")
        if exfiltration:
            required_rank = min(required_rank, 1)   # P1
            triggers.append("exfiltration_confirmed")
        if affected_individuals >= 10_000:
            required_rank = min(required_rank, 1)   # P1
            triggers.append(f"affected_individuals>10000 ({affected_individuals})")
        if high_risk_ai:
            required_rank = min(required_rank, 2)   # P2
            triggers.append("high_risk_ai_system_affected")
        if privacy_impact:
            required_rank = min(required_rank, 2)   # P2
            triggers.append("privacy_impact_confirmed")
        if affected_individuals >= 100:
            required_rank = min(required_rank, 2)   # P2
            triggers.append(f"affected_individuals>=100 ({affected_individuals})")
        if regulatory_triggered:
            required_rank = min(required_rank, 2)   # P2
            triggers.append("regulatory_obligation_triggered")

        new_severity = _RANK_SEVERITY[required_rank]
        escalated    = False

        if _SEVERITY_RANK[new_severity] < _SEVERITY_RANK[self._severity]:
            ev = EscalationEvent(
                trigger      = " | ".join(triggers),
                old_severity = self._severity,
                new_severity = new_severity,
                escalated_by = escalated_by,
                timestamp    = datetime.now(timezone.utc).isoformat(),
                rationale    = f"Escalated from {self._severity} to {new_severity}: {', '.join(triggers)}",
            )
            self._history.append(ev)
            self._severity = new_severity
            escalated      = True

        return EscalationResult(
            incident_id        = self._id,
            current_severity   = self._severity,
            escalation_history = list(self._history),
            escalated          = escalated,
        )

    def force_escalate(
        self,
        new_severity: str,
        escalated_by: str,
        rationale:    str,
    ) -> None:
        """Manual escalation override by incident commander."""
        if new_severity not in _SEVERITY_RANK:
            raise ValueError(f"Invalid severity: {new_severity}")
        if _SEVERITY_RANK[new_severity] < _SEVERITY_RANK[self._severity]:
            ev = EscalationEvent(
                trigger=f"manual_override_by_{escalated_by}",
                old_severity=self._severity, new_severity=new_severity,
                escalated_by=escalated_by,
                timestamp=datetime.now(timezone.utc).isoformat(),
                rationale=rationale,
            )
            self._history.append(ev)
            self._severity = new_severity
