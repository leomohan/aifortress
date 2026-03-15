"""
policy_engine.py  —  RBAC + ABAC evaluation engine and audit logger
AI Fortress · Chapter 1 · Code Sample 1.B

Decision priority:
  1. Unknown role          → DENY
  2. Unknown classification → DENY
  3. Classification > role ceiling → DENY
  4. Action not in role    → DENY
  5. Resource prefix mismatch → DENY
  6. All pass              → PERMIT
"""
from __future__ import annotations
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict
from roles import Role, Classification


@dataclass
class AccessDecision:
    permitted:      bool
    subject:        str
    role_name:      str
    action:         str
    resource:       str
    classification: str
    reason:         str
    timestamp:      str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)


class PolicyEngine:
    def __init__(self, roles: Dict[str, Role]):
        self.roles = roles

    def evaluate(
        self,
        subject:        str,
        role:           str,
        action:         str,
        resource:       str,
        classification: str = "INTERNAL",
    ) -> AccessDecision:
        kw = dict(subject=subject, role_name=role, action=action,
                  resource=resource, classification=classification)

        r = self.roles.get(role)
        if r is None:
            return AccessDecision(permitted=False, reason=f"Unknown role '{role}'", **kw)

        try:
            cl = Classification[classification.upper()]
        except KeyError:
            return AccessDecision(permitted=False, reason=f"Unknown classification '{classification}'", **kw)

        if not r.can_access_classification(cl):
            return AccessDecision(
                permitted=False,
                reason=f"Role '{role}' ceiling={r.classification_ceiling.name}; resource={classification}",
                **kw,
            )
        if not r.can_act(action):
            return AccessDecision(permitted=False, reason=f"Role '{role}' does not permit action '{action}'", **kw)

        if not r.can_access_prefix(resource):
            return AccessDecision(permitted=False, reason=f"Role '{role}' has no prefix match for: {resource}", **kw)

        return AccessDecision(permitted=True, reason="All checks passed", **kw)


class AuditLogger:
    """Append-only JSON Lines audit log. Never deletes or overwrites entries."""
    def __init__(self, log_path: str | Path):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, decision: AccessDecision) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(decision.to_dict()) + "\n")

    def tail(self, n: int = 20) -> list[dict]:
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text().strip().splitlines()
        return [json.loads(l) for l in lines[-n:]]

    def denied_last_hour(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        cutoff = datetime.now(timezone.utc).timestamp() - 3600
        out = []
        for line in self.log_path.read_text().strip().splitlines():
            e = json.loads(line)
            if not e["permitted"]:
                ts = datetime.fromisoformat(e["timestamp"]).timestamp()
                if ts >= cutoff:
                    out.append(e)
        return out
