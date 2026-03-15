"""
jit_access.py  —  Just-in-time elevated access for ML infrastructure
AI Fortress · Chapter 11 · Code Sample 11.B

Implements a JIT access workflow for high-risk ML operations:
  1. REQUEST  — principal submits a request with justification
  2. APPROVE  — approver (or auto-approval rule) grants the request
  3. ACTIVATE — principal activates the approved grant (starts session)
  4. EXPIRE   — access window ends; permission automatically revoked

Supported ML privileged operations:
  model:promote     — promote a candidate model to production
  cluster:admin     — administrative access to GPU/CPU clusters
  registry:admin    — full control of model registry
  data:admin        — write/delete access to sensitive datasets
  secrets:admin     — access to ML platform credential store
  pipeline:override — bypass pipeline approval gates
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional

_PRIVILEGED_OPERATIONS = {
    "model:promote",
    "cluster:admin",
    "registry:admin",
    "data:admin",
    "secrets:admin",
    "pipeline:override",
}

_DEFAULT_TTL_SECS = 3600    # 1 hour


@dataclass
class JITRequest:
    request_id:   str
    principal:    str
    operation:    str
    resource:     str
    justification: str
    requested_at: str
    ttl_seconds:  int
    status:       str = "pending"    # pending | approved | denied | active | expired | revoked
    approved_by:  str = ""
    approved_at:  str = ""
    activated_at: str = ""
    expires_at:   str = ""
    deny_reason:  str = ""


@dataclass
class JITDecision:
    request_id:  str
    approved:    bool
    reason:      str


class JITAccessManager:
    """
    Manages just-in-time elevated access for ML operations.

    Parameters
    ----------
    auto_approve_fn  : Optional callable(JITRequest) → bool.
                       If provided, called on every new request;
                       returning True auto-approves, False requires manual approval.
    default_ttl      : Default access window in seconds (default 3600).
    audit_path       : Optional JSON Lines path for JIT events.
    """

    def __init__(
        self,
        auto_approve_fn: Optional[Callable] = None,
        default_ttl:     int = _DEFAULT_TTL_SECS,
        audit_path:      Optional[str | Path] = None,
    ):
        self._requests:    Dict[str, JITRequest] = {}
        self._auto_approve = auto_approve_fn
        self._default_ttl  = default_ttl
        self._audit        = Path(audit_path) if audit_path else None

    # ── Workflow steps ────────────────────────────────────────────────────────

    def request_access(
        self,
        principal:     str,
        operation:     str,
        resource:      str,
        justification: str,
        ttl_seconds:   Optional[int] = None,
    ) -> JITRequest:
        """Submit a JIT access request."""
        if operation not in _PRIVILEGED_OPERATIONS:
            raise ValueError(f"'{operation}' is not a recognised privileged operation. "
                             f"Allowed: {sorted(_PRIVILEGED_OPERATIONS)}")
        if not justification or len(justification.strip()) < 10:
            raise ValueError("Justification must be at least 10 characters")

        req = JITRequest(
            request_id    = str(uuid.uuid4()),
            principal     = principal,
            operation     = operation,
            resource      = resource,
            justification = justification,
            requested_at  = datetime.now(timezone.utc).isoformat(),
            ttl_seconds   = ttl_seconds or self._default_ttl,
        )
        self._requests[req.request_id] = req
        self._log("jit_requested", request_id=req.request_id,
                  principal=principal, operation=operation, resource=resource)

        # Auto-approve if rule provided
        if self._auto_approve and self._auto_approve(req):
            self.approve(req.request_id, approver="auto-approval-rule")

        return req

    def approve(
        self,
        request_id: str,
        approver:   str,
    ) -> JITDecision:
        """Approve a pending JIT request."""
        req = self._get_pending(request_id)
        req.status      = "approved"
        req.approved_by = approver
        req.approved_at = datetime.now(timezone.utc).isoformat()
        self._log("jit_approved", request_id=request_id, approver=approver,
                  operation=req.operation, principal=req.principal)
        return JITDecision(request_id=request_id, approved=True,
                           reason=f"Approved by {approver}")

    def deny(
        self,
        request_id: str,
        approver:   str,
        reason:     str = "",
    ) -> JITDecision:
        """Deny a pending JIT request."""
        req             = self._get_pending(request_id)
        req.status      = "denied"
        req.approved_by = approver
        req.deny_reason = reason
        self._log("jit_denied", request_id=request_id, approver=approver,
                  reason=reason)
        return JITDecision(request_id=request_id, approved=False, reason=reason)

    def activate(self, request_id: str) -> JITRequest:
        """Activate an approved JIT request, starting the access window."""
        req = self._requests.get(request_id)
        if req is None:
            raise KeyError(f"Request '{request_id}' not found")
        if req.status != "approved":
            raise ValueError(f"Request must be approved before activation (status={req.status})")

        now            = datetime.now(timezone.utc)
        req.status      = "active"
        req.activated_at = now.isoformat()
        req.expires_at  = (now + timedelta(seconds=req.ttl_seconds)).isoformat()
        self._log("jit_activated", request_id=request_id, principal=req.principal,
                  operation=req.operation, expires_at=req.expires_at)
        return req

    def revoke(self, request_id: str, revoked_by: str = "") -> bool:
        """Immediately revoke an active JIT session."""
        req = self._requests.get(request_id)
        if req is None or req.status != "active":
            return False
        req.status = "revoked"
        self._log("jit_revoked", request_id=request_id,
                  principal=req.principal, operation=req.operation,
                  revoked_by=revoked_by)
        return True

    def check_access(
        self,
        principal: str,
        operation: str,
        resource:  str = "*",
        now:       Optional[datetime] = None,
    ) -> bool:
        """Return True if principal has an active, non-expired JIT grant."""
        now = now or datetime.now(timezone.utc)
        for req in self._requests.values():
            if req.principal != principal:
                continue
            if req.operation != operation:
                continue
            if req.resource not in ("*", resource) and resource != "*":
                continue
            if req.status != "active":
                continue
            if req.expires_at:
                exp = datetime.fromisoformat(req.expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if now > exp:
                    req.status = "expired"
                    self._log("jit_expired", request_id=req.request_id,
                              principal=principal, operation=operation)
                    continue
            return True
        return False

    def pending_requests(self) -> List[JITRequest]:
        return [r for r in self._requests.values() if r.status == "pending"]

    def active_sessions(self) -> List[JITRequest]:
        return [r for r in self._requests.values() if r.status == "active"]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_pending(self, request_id: str) -> JITRequest:
        req = self._requests.get(request_id)
        if req is None:
            raise KeyError(f"Request '{request_id}' not found")
        if req.status != "pending":
            raise ValueError(f"Request is not pending (status={req.status})")
        return req

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
