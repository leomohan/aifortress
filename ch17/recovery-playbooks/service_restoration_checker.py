"""
service_restoration_checker.py  —  Service restoration readiness checker
AI Fortress · Chapter 17 · Code Sample 17.D

Validates that all required checks pass before an AI service is
restored to production after an incident. Enforces a gated
restoration checklist covering: integrity, security, fairness,
monitoring, and authorisation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


_DEFAULT_GATES = [
    "model_integrity_verified",
    "vulnerability_patched",
    "fairness_evaluation_passed",
    "monitoring_alerts_configured",
    "rollback_plan_in_place",
    "incident_commander_approved",
    "legal_dpo_cleared",
    "penetration_test_passed",
]


@dataclass
class RestorationGate:
    gate:      str
    passed:    bool
    verified_by: Optional[str]
    notes:     str


@dataclass
class RestorationCheckResult:
    service_name:    str
    incident_id:     str
    gates:           List[RestorationGate]
    n_passed:        int
    n_total:         int
    ready:           bool
    blocked_gates:   List[str]
    checked_at:      str
    verdict:         str   # "READY_TO_RESTORE"|"BLOCKED"|"PARTIAL"


class ServiceRestorationChecker:
    """
    Validates restoration readiness of an AI service after an incident.

    Parameters
    ----------
    required_gates : List of gate names that must pass before restoration.
                     Defaults to _DEFAULT_GATES.
    """

    def __init__(self, required_gates: Optional[List[str]] = None):
        self._gates = required_gates or _DEFAULT_GATES

    def check(
        self,
        service_name: str,
        incident_id:  str,
        gate_results: Dict[str, dict],   # gate → {"passed": bool, "verified_by": str, "notes": str}
    ) -> RestorationCheckResult:
        """
        Evaluate restoration readiness.

        Parameters
        ----------
        gate_results : Dict mapping gate name → result dict with keys:
                       passed (bool), verified_by (str), notes (str).
        """
        gates: List[RestorationGate] = []
        for g in self._gates:
            res = gate_results.get(g, {})
            gates.append(RestorationGate(
                gate        = g,
                passed      = bool(res.get("passed", False)),
                verified_by = res.get("verified_by"),
                notes       = res.get("notes", ""),
            ))

        n_passed = sum(1 for g in gates if g.passed)
        blocked  = [g.gate for g in gates if not g.passed]
        ready    = len(blocked) == 0

        verdict = (
            "READY_TO_RESTORE" if ready
            else "PARTIAL"     if n_passed >= len(self._gates) // 2
            else "BLOCKED"
        )

        return RestorationCheckResult(
            service_name  = service_name,
            incident_id   = incident_id,
            gates         = gates,
            n_passed      = n_passed,
            n_total       = len(self._gates),
            ready         = ready,
            blocked_gates = blocked,
            checked_at    = datetime.now(timezone.utc).isoformat(),
            verdict       = verdict,
        )
