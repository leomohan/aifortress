"""
rbac_engine.py  —  RBAC engine for ML infrastructure
AI Fortress · Chapter 11 · Code Sample 11.A

Implements role-based access control tailored to ML platform access patterns.

ML permission catalogue:
  model:read            — read model artefacts and metadata
  model:write           — upload or update model artefacts
  model:deploy          — promote model to production endpoint
  model:delete          — delete model versions
  training:run          — submit training jobs
  training:read         — view training job status and metrics
  data:read             — read training / evaluation datasets
  data:write            — write or delete dataset partitions
  pipeline:execute      — trigger ML pipeline runs
  pipeline:read         — view pipeline DAGs and run history
  registry:read         — browse model registry
  registry:write        — register new models and versions
  infra:read            — view GPU/CPU cluster status
  infra:manage          — scale or configure compute resources
  secrets:read          — read ML service credentials
  audit:read            — view audit logs

Built-in ML roles (least → most privilege):
  auditor          → audit:read, training:read, pipeline:read, registry:read
  model-reviewer   → model:read, training:read, registry:read
  data-scientist   → model:read/write, training:run/read, data:read, pipeline:read, registry:read
  ml-engineer      → data-scientist permissions + pipeline:execute, registry:write, infra:read
  mlops-admin      → all permissions
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set


# ── Permission catalogue ──────────────────────────────────────────────────────

ALL_PERMISSIONS: FrozenSet[str] = frozenset({
    "model:read", "model:write", "model:deploy", "model:delete",
    "training:run", "training:read",
    "data:read", "data:write",
    "pipeline:execute", "pipeline:read",
    "registry:read", "registry:write",
    "infra:read", "infra:manage",
    "secrets:read",
    "audit:read",
})

_ROLE_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "auditor": frozenset({"audit:read", "training:read", "pipeline:read", "registry:read"}),
    "model-reviewer": frozenset({"model:read", "training:read", "registry:read"}),
    "data-scientist": frozenset({
        "model:read", "model:write",
        "training:run", "training:read",
        "data:read",
        "pipeline:read",
        "registry:read",
    }),
    "ml-engineer": frozenset({
        "model:read", "model:write",
        "training:run", "training:read",
        "data:read",
        "pipeline:execute", "pipeline:read",
        "registry:read", "registry:write",
        "infra:read",
    }),
    "mlops-admin": ALL_PERMISSIONS,
}

# Role inheritance (child inherits parent's permissions)
_ROLE_PARENTS: Dict[str, List[str]] = {
    "model-reviewer": [],
    "auditor":        [],
    "data-scientist": ["model-reviewer"],
    "ml-engineer":    ["data-scientist"],
    "mlops-admin":    ["ml-engineer"],
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class RoleAssignment:
    principal:  str
    role:       str
    granted_by: str
    granted_at: str
    expires_at: str = ""       # ISO8601 or "" = permanent
    assignment_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class AccessDecision:
    allowed:    bool
    principal:  str
    permission: str
    resource:   str
    reason:     str
    roles:      List[str]      # roles that contributed
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── RBAC engine ───────────────────────────────────────────────────────────────

class RBACEngine:
    """
    Role-based access control engine for ML infrastructure.

    Parameters
    ----------
    custom_roles : Optional dict of {role_name: set_of_permissions} to extend
                   the built-in role catalogue.
    audit_path   : Optional JSON Lines path for access decisions.
    """

    def __init__(
        self,
        custom_roles: Optional[Dict[str, Set[str]]] = None,
        audit_path:   Optional[str | Path] = None,
    ):
        self._role_perms: Dict[str, FrozenSet[str]] = dict(_ROLE_PERMISSIONS)
        if custom_roles:
            for role, perms in custom_roles.items():
                self._role_perms[role] = frozenset(perms)

        self._assignments: Dict[str, List[RoleAssignment]] = {}  # principal → list
        self._audit = Path(audit_path) if audit_path else None

    # ── Assignment management ─────────────────────────────────────────────────

    def assign_role(
        self,
        principal:  str,
        role:       str,
        granted_by: str,
        expires_at: str = "",
    ) -> RoleAssignment:
        """Assign a role to a principal."""
        if role not in self._role_perms:
            raise ValueError(f"Unknown role '{role}'. "
                             f"Known roles: {sorted(self._role_perms)}")
        assignment = RoleAssignment(
            principal  = principal,
            role       = role,
            granted_by = granted_by,
            granted_at = datetime.now(timezone.utc).isoformat(),
            expires_at = expires_at,
        )
        self._assignments.setdefault(principal, []).append(assignment)
        self._write_audit("role_assigned", principal=principal, role=role,
                          granted_by=granted_by, expires_at=expires_at)
        return assignment

    def revoke_role(self, principal: str, role: str, revoked_by: str = "") -> int:
        """Revoke all assignments of `role` from `principal`. Returns count revoked."""
        before = len(self._assignments.get(principal, []))
        self._assignments[principal] = [
            a for a in self._assignments.get(principal, []) if a.role != role
        ]
        after  = len(self._assignments.get(principal, []))
        count  = before - after
        if count:
            self._write_audit("role_revoked", principal=principal, role=role,
                              revoked_by=revoked_by)
        return count

    def get_active_assignments(self, principal: str) -> List[RoleAssignment]:
        """Return all non-expired role assignments for a principal."""
        now = datetime.now(timezone.utc)
        result = []
        for a in self._assignments.get(principal, []):
            if a.expires_at:
                exp = datetime.fromisoformat(a.expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if now > exp:
                    continue
            result.append(a)
        return result

    # ── Permission resolution ─────────────────────────────────────────────────

    def get_effective_permissions(self, principal: str) -> FrozenSet[str]:
        """Return all permissions granted to `principal` via active roles."""
        perms: Set[str] = set()
        for assignment in self.get_active_assignments(principal):
            perms |= self._resolve_role_permissions(assignment.role)
        return frozenset(perms)

    def check(
        self,
        principal:  str,
        permission: str,
        resource:   str = "*",
    ) -> AccessDecision:
        """Check whether `principal` has `permission` on `resource`."""
        active  = self.get_active_assignments(principal)
        roles   = [a.role for a in active]
        allowed = permission in self.get_effective_permissions(principal)

        decision = AccessDecision(
            allowed    = allowed,
            principal  = principal,
            permission = permission,
            resource   = resource,
            reason     = ("Permission granted via roles: " + str(roles))
                         if allowed else "No role grants this permission",
            roles      = roles,
        )
        self._write_audit("access_check", principal=principal, permission=permission,
                          resource=resource, allowed=allowed)
        return decision

    def list_principals_with_permission(self, permission: str) -> List[str]:
        """Return all principals who currently have a given permission."""
        result = []
        for principal in self._assignments:
            if permission in self.get_effective_permissions(principal):
                result.append(principal)
        return sorted(result)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _resolve_role_permissions(self, role: str) -> FrozenSet[str]:
        """Resolve permissions for a role including inherited permissions."""
        perms: Set[str] = set(self._role_perms.get(role, frozenset()))
        for parent in _ROLE_PARENTS.get(role, []):
            perms |= self._resolve_role_permissions(parent)
        return frozenset(perms)

    def _write_audit(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **kwargs,
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
