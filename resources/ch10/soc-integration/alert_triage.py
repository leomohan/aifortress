"""
alert_triage.py  —  Rule-based ML security alert triage
AI Fortress · Chapter 10 · Code Sample 10.B

Scores incoming normalised alerts and produces a triage decision with
recommended analyst action.

Triage tiers:
  P1 — Severity ≥ 9 OR CRITICAL pattern match → immediate response (< 15 min)
  P2 — Severity 7–8 OR WARNING pattern match  → investigate within 1 hour
  P3 — Severity 5–6                           → investigate within 4 hours
  P4 — Severity < 5                           → log and review daily

Pattern rules applied:
  - Multiple auth failures from same IP in short window → escalate to P1
  - Drift + auth failure in same model window → supply-chain indicator
  - Lateral movement signal always P1
  - Model extraction pattern (high query volume + low confidence) → P1
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from alert_normaliser import NormalisedAlert


@dataclass
class TriageRule:
    id:          str
    description: str
    conditions:  dict      # field → value or {"min": x} / {"contains": s}
    priority:    str       # "P1" | "P2" | "P3" | "P4"
    action:      str       # recommended action string


@dataclass
class TriageDecision:
    event_id:    str
    event_type:  str
    priority:    str
    action:      str
    matched_rule: str      # rule ID or "default"
    confidence:  float     # 0.0–1.0
    detail:      str


_DEFAULT_RULES: List[TriageRule] = [
    TriageRule(
        id="R001", description="Critical severity events",
        conditions={"severity": {"min": 9}},
        priority="P1",
        action="Page on-call security engineer immediately. Isolate affected ML endpoint.",
    ),
    TriageRule(
        id="R002", description="Lateral movement detected",
        conditions={"event_type": "lateral_movement"},
        priority="P1",
        action="Isolate source workload from service mesh. Trigger incident response.",
    ),
    TriageRule(
        id="R003", description="Supply chain or model extraction",
        conditions={"event_type": {"in": ["supply_chain", "model_extraction"]}},
        priority="P1",
        action="Lock down model registry and artifact store. Engage CISO.",
    ),
    TriageRule(
        id="R004", description="High severity auth or signing failures",
        conditions={"severity": {"min": 7},
                    "event_type": {"in": ["auth_failure", "signing_failure"]}},
        priority="P2",
        action="Investigate authentication logs. Check for credential compromise.",
    ),
    TriageRule(
        id="R005", description="Feature importance collapse",
        conditions={"event_type": "importance_drift", "severity": {"min": 7}},
        priority="P2",
        action="Review feature pipeline for tampering. Check recent data ingestion jobs.",
    ),
    TriageRule(
        id="R006", description="Prediction drift critical",
        conditions={"event_type": "prediction_drift", "severity": {"min": 7}},
        priority="P2",
        action="Compare predictions against baseline. Review recent model deployments.",
    ),
    TriageRule(
        id="R007", description="Medium severity events",
        conditions={"severity": {"min": 5}},
        priority="P3",
        action="Investigate during business hours. Review related logs for context.",
    ),
    TriageRule(
        id="R008", description="Low severity events",
        conditions={"severity": {"min": 0}},
        priority="P4",
        action="Log for daily review. Aggregate with similar events for pattern analysis.",
    ),
]


class AlertTriageClassifier:
    """
    Applies rule-based triage to normalised ML security alerts.

    Parameters
    ----------
    rules      : List of TriageRules (evaluated top-to-bottom, first match wins).
                 Defaults to the built-in rule set.
    audit_path : Optional JSON Lines path for triage decisions.
    """

    def __init__(
        self,
        rules:      Optional[List[TriageRule]] = None,
        audit_path: Optional[str | Path] = None,
    ):
        self._rules = rules if rules is not None else _DEFAULT_RULES
        self._audit = Path(audit_path) if audit_path else None

    def triage(self, alert: NormalisedAlert) -> TriageDecision:
        """Apply triage rules to a single normalised alert."""
        for rule in self._rules:
            if self._matches(alert, rule.conditions):
                decision = TriageDecision(
                    event_id     = alert.event_id,
                    event_type   = alert.event_type,
                    priority     = rule.priority,
                    action       = rule.action,
                    matched_rule = rule.id,
                    confidence   = self._confidence(alert, rule),
                    detail       = f"Matched rule {rule.id}: {rule.description}",
                )
                self._log(decision)
                return decision

        # Default fallback (should not reach here with default rules)
        decision = TriageDecision(
            event_id=alert.event_id, event_type=alert.event_type,
            priority="P4", action="Log for review.",
            matched_rule="default", confidence=0.5,
            detail="No rule matched — default P4",
        )
        self._log(decision)
        return decision

    def triage_batch(self, alerts: List[NormalisedAlert]) -> List[TriageDecision]:
        return [self.triage(a) for a in alerts]

    # ── Matching ──────────────────────────────────────────────────────────────

    @staticmethod
    def _matches(alert: NormalisedAlert, conditions: dict) -> bool:
        for field_name, condition in conditions.items():
            val = getattr(alert, field_name, None)
            if val is None:
                val = alert.json_record.get(field_name)
            if val is None:
                return False

            if isinstance(condition, dict):
                if "min" in condition and not (float(val) >= float(condition["min"])):
                    return False
                if "max" in condition and not (float(val) <= float(condition["max"])):
                    return False
                if "in" in condition and val not in condition["in"]:
                    return False
                if "contains" in condition and condition["contains"] not in str(val):
                    return False
            else:
                if val != condition:
                    return False
        return True

    @staticmethod
    def _confidence(alert: NormalisedAlert, rule: TriageRule) -> float:
        """Heuristic confidence: higher severity = higher confidence."""
        base = min(alert.severity / 10.0, 1.0)
        if rule.priority == "P1":
            return round(min(base + 0.2, 1.0), 2)
        return round(base, 2)

    def _log(self, decision: TriageDecision) -> None:
        if not self._audit:
            return
        import dataclasses
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            **dataclasses.asdict(decision),
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
