"""
authz_policy_engine.py  —  Declarative inter-service authorisation policy engine
AI Fortress · Chapter 9 · Code Sample 9.B

Evaluates whether a source workload may call a destination service, using
a declarative policy that maps SPIFFE IDs to allowed operations.

Policy format (list of rules evaluated top-to-bottom, first match wins):
  [
    {
      "id":          "allow-inference-to-feature-store",
      "source":      "spiffe://platform/ns/inference/sa/model-server",
      "destination": "feature-store",
      "methods":     ["GET"],
      "paths":       ["/v1/features/*"],
      "effect":      "allow"
    },
    {
      "id":     "deny-all",
      "source": "*",
      "destination": "*",
      "methods": ["*"],
      "paths":   ["*"],
      "effect":  "deny"
    }
  ]

Matching rules:
  - "*" in source/destination/methods/paths matches anything
  - Path patterns support trailing "*" wildcard
  - Default effect when no rule matches: DENY
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class AuthzRule:
    id:          str
    source:      str       # SPIFFE ID or "*"
    destination: str       # service name or "*"
    methods:     List[str] # HTTP methods or ["*"]
    paths:       List[str] # path patterns or ["*"]
    effect:      str       # "allow" | "deny"


@dataclass
class AuthzDecision:
    allowed:     bool
    rule_id:     str       # which rule matched, or "default-deny"
    effect:      str       # "allow" | "deny"
    source:      str
    destination: str
    method:      str
    path:        str
    reason:      str


class AuthzPolicyEngine:
    """
    Evaluates inter-service access requests against a declarative policy.

    Default behaviour: DENY if no rule matches (default-deny posture).

    Parameters
    ----------
    rules      : List of AuthzRule objects (evaluated in order).
    audit_path : Optional path for JSON Lines decision log.
    """

    def __init__(
        self,
        rules:      Optional[List[AuthzRule]] = None,
        audit_path: Optional[str | Path] = None,
    ):
        self._rules = rules or []
        self._audit = Path(audit_path) if audit_path else None

    @classmethod
    def from_dict(cls, policy: list, audit_path: Optional[str | Path] = None) -> "AuthzPolicyEngine":
        """Load policy from a list of rule dicts."""
        rules = []
        for r in policy:
            rules.append(AuthzRule(
                id          = r.get("id", "unnamed"),
                source      = r.get("source", "*"),
                destination = r.get("destination", "*"),
                methods     = [m.upper() for m in r.get("methods", ["*"])],
                paths       = r.get("paths", ["*"]),
                effect      = r.get("effect", "deny").lower(),
            ))
        return cls(rules=rules, audit_path=audit_path)

    @classmethod
    def from_file(cls, path: str | Path, audit_path: Optional[str | Path] = None) -> "AuthzPolicyEngine":
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(policy, audit_path=audit_path)

    def evaluate(
        self,
        source:      str,   # SPIFFE ID of caller
        destination: str,   # destination service name
        method:      str,   # HTTP method
        path:        str,   # request path
    ) -> AuthzDecision:
        """Evaluate an access request. Returns AuthzDecision."""
        method_up = method.upper()

        for rule in self._rules:
            if not self._match_source(rule.source, source):
                continue
            if not self._match_dest(rule.destination, destination):
                continue
            if not self._match_method(rule.methods, method_up):
                continue
            if not self._match_path(rule.paths, path):
                continue

            # Rule matched
            allowed = rule.effect == "allow"
            decision = AuthzDecision(
                allowed     = allowed,
                rule_id     = rule.id,
                effect      = rule.effect,
                source      = source,
                destination = destination,
                method      = method_up,
                path        = path,
                reason      = f"Matched rule '{rule.id}' → {rule.effect}",
            )
            self._log(decision)
            return decision

        # No rule matched — default deny
        decision = AuthzDecision(
            allowed     = False,
            rule_id     = "default-deny",
            effect      = "deny",
            source      = source,
            destination = destination,
            method      = method_up,
            path        = path,
            reason      = "No matching policy rule (default-deny)",
        )
        self._log(decision)
        return decision

    def add_rule(self, rule: AuthzRule, position: int = -1) -> None:
        """Insert a rule at `position` (-1 = append)."""
        if position < 0:
            self._rules.append(rule)
        else:
            self._rules.insert(position, rule)

    # ── Matching helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _match_source(pattern: str, source: str) -> bool:
        return pattern == "*" or pattern == source or fnmatch.fnmatch(source, pattern)

    @staticmethod
    def _match_dest(pattern: str, dest: str) -> bool:
        return pattern == "*" or pattern == dest or fnmatch.fnmatch(dest, pattern)

    @staticmethod
    def _match_method(allowed_methods: List[str], method: str) -> bool:
        return "*" in allowed_methods or method in allowed_methods

    @staticmethod
    def _match_path(patterns: List[str], path: str) -> bool:
        for pat in patterns:
            if pat == "*" or pat == path:
                return True
            # Trailing wildcard: "/v1/features/*" matches "/v1/features/user123"
            if pat.endswith("*") and path.startswith(pat[:-1]):
                return True
            if fnmatch.fnmatch(path, pat):
                return True
        return False

    def _log(self, decision: AuthzDecision) -> None:
        if self._audit is None:
            return
        import dataclasses
        record = {
            "ts":     datetime.now(timezone.utc).isoformat(),
            **dataclasses.asdict(decision),
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
