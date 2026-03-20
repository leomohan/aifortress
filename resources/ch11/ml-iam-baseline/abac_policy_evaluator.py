"""
abac_policy_evaluator.py  —  Attribute-based access control for ML resources
AI Fortress · Chapter 11 · Code Sample 11.A

Evaluates ABAC policies at request time. Policies are expressed as JSON
rules matching on subject, resource, and context attributes.

Policy format:
  [
    {
      "id":     "deny-prod-without-mfa",
      "effect": "deny",
      "conditions": {
        "resource.environment": "production",
        "context.mfa":          {"ne": true}
      },
      "description": "Block production access without MFA"
    },
    {
      "id":     "allow-own-model",
      "effect": "allow",
      "conditions": {
        "resource.owner": {"eq_subject": "sub.user_id"}
      },
      "description": "Allow users to access their own models"
    }
  ]

Condition operators:
  eq         — equals (default if value is scalar)
  ne         — not equals
  in         — value is in list
  not_in     — value not in list
  gt / gte   — greater than / or equal
  lt / lte   — less than / or equal
  contains   — string contains
  eq_subject — attribute value equals another attribute (cross-attribute)
  exists     — attribute exists (bool)

Evaluation order: DENY policies evaluated first; first DENY wins.
If no DENY matches, first ALLOW wins. Default effect: DENY.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ABACRequest:
    subject:  Dict[str, Any]    # e.g. {"user_id": "alice", "team": "nlp", "mfa": True}
    resource: Dict[str, Any]    # e.g. {"type": "model", "owner": "alice", "env": "prod"}
    context:  Dict[str, Any]    # e.g. {"ip": "10.0.0.1", "hour": 14, "mfa": True}
    action:   str               # e.g. "model:deploy"


@dataclass
class ABACDecision:
    allowed:      bool
    matched_policy: str          # policy id or "default-deny"
    effect:       str            # "allow" | "deny"
    reason:       str


@dataclass
class ABACPolicy:
    id:          str
    effect:      str             # "allow" | "deny"
    conditions:  Dict[str, Any]
    description: str = ""
    actions:     List[str] = field(default_factory=list)  # [] = all actions


class ABACPolicyEvaluator:
    """
    Evaluates ABAC policies against access requests.

    Parameters
    ----------
    policies   : List of ABACPolicy objects.
    audit_path : Optional JSON Lines path.
    """

    def __init__(
        self,
        policies:   Optional[List[ABACPolicy]] = None,
        audit_path: Optional[str | Path] = None,
    ):
        self._policies = policies or []
        self._audit    = Path(audit_path) if audit_path else None

    @classmethod
    def from_list(
        cls,
        policy_list: list,
        audit_path:  Optional[str | Path] = None,
    ) -> "ABACPolicyEvaluator":
        policies = [
            ABACPolicy(
                id          = p["id"],
                effect      = p.get("effect", "deny"),
                conditions  = p.get("conditions", {}),
                description = p.get("description", ""),
                actions     = p.get("actions", []),
            )
            for p in policy_list
        ]
        return cls(policies=policies, audit_path=audit_path)

    @classmethod
    def from_file(cls, path: str | Path, audit_path: Optional[str | Path] = None) -> "ABACPolicyEvaluator":
        return cls.from_list(json.loads(Path(path).read_text()), audit_path=audit_path)

    def evaluate(self, request: ABACRequest) -> ABACDecision:
        """Evaluate an access request. DENY policies checked first."""
        flat = self._flatten(request)

        # 1. Check DENY policies
        for policy in self._policies:
            if policy.effect != "deny":
                continue
            if policy.actions and request.action not in policy.actions:
                continue
            if self._matches(flat, policy.conditions, request):
                decision = ABACDecision(
                    allowed       = False,
                    matched_policy = policy.id,
                    effect        = "deny",
                    reason        = f"Denied by policy '{policy.id}': {policy.description}",
                )
                self._log(request, decision)
                return decision

        # 2. Check ALLOW policies
        for policy in self._policies:
            if policy.effect != "allow":
                continue
            if policy.actions and request.action not in policy.actions:
                continue
            if self._matches(flat, policy.conditions, request):
                decision = ABACDecision(
                    allowed       = True,
                    matched_policy = policy.id,
                    effect        = "allow",
                    reason        = f"Allowed by policy '{policy.id}': {policy.description}",
                )
                self._log(request, decision)
                return decision

        # 3. Default deny
        decision = ABACDecision(
            allowed       = False,
            matched_policy = "default-deny",
            effect        = "deny",
            reason        = "No matching allow policy (default-deny posture)",
        )
        self._log(request, decision)
        return decision

    def add_policy(self, policy: ABACPolicy) -> None:
        self._policies.append(policy)

    # ── Matching ──────────────────────────────────────────────────────────────

    @staticmethod
    def _flatten(req: ABACRequest) -> Dict[str, Any]:
        flat: Dict[str, Any] = {}
        for k, v in req.subject.items():
            flat[f"sub.{k}"] = v
        for k, v in req.resource.items():
            flat[f"resource.{k}"] = v
        for k, v in req.context.items():
            flat[f"context.{k}"] = v
        flat["action"] = req.action
        return flat

    @staticmethod
    def _matches(flat: Dict[str, Any], conditions: Dict[str, Any], req: ABACRequest) -> bool:
        for attr, condition in conditions.items():
            val = flat.get(attr)

            if isinstance(condition, dict):
                op  = next(iter(condition))
                cmp = condition[op]

                if op == "eq":
                    if val != cmp:
                        return False
                elif op == "ne":
                    if val == cmp:
                        return False
                elif op == "in":
                    if val not in cmp:
                        return False
                elif op == "not_in":
                    if val in cmp:
                        return False
                elif op == "gt":
                    if not (val is not None and val > cmp):
                        return False
                elif op == "gte":
                    if not (val is not None and val >= cmp):
                        return False
                elif op == "lt":
                    if not (val is not None and val < cmp):
                        return False
                elif op == "lte":
                    if not (val is not None and val <= cmp):
                        return False
                elif op == "contains":
                    if val is None or cmp not in str(val):
                        return False
                elif op == "eq_subject":
                    # Compare attribute value to another attribute's value
                    other_val = flat.get(cmp)
                    if val != other_val:
                        return False
                elif op == "exists":
                    present = val is not None
                    if present != cmp:
                        return False
            else:
                # Scalar: implicit equality
                if val != condition:
                    return False
        return True

    def _log(self, req: ABACRequest, decision: ABACDecision) -> None:
        if not self._audit:
            return
        record = {
            "ts":       datetime.now(timezone.utc).isoformat(),
            "action":   req.action,
            "allowed":  decision.allowed,
            "policy":   decision.matched_policy,
            "subject":  req.subject,
            "resource": req.resource,
            "context":  req.context,
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
