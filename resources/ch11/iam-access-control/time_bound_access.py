"""
time_bound_access.py  —  Time-bound access grants for ML infrastructure
AI Fortress · Chapter 11 · Code Sample 11.A

Manages temporary access grants with configurable TTL and automatic
expiry checking. Designed for:
  - Emergency / break-glass access to production models
  - Temporary data-science access to sensitive training datasets
  - Limited-duration pipeline execution rights for contractors
  - Time-boxed model deployment windows

Features:
  - Grant creation with TTL in seconds, minutes, hours, or days
  - Expiry check on every access decision (no standing access drift)
  - Near-expiry notification list (configurable warn threshold)
  - Clean-up sweep to remove fully-expired grants
  - Structured audit log of grant/revoke/access events
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class TimeBoundGrant:
    grant_id:    str
    principal:   str
    permission:  str
    resource:    str          # "*" for any resource
    granted_by:  str
    granted_at:  str          # ISO8601
    expires_at:  str          # ISO8601
    reason:      str = ""
    revoked:     bool = False
    revoked_at:  str  = ""
    revoked_by:  str  = ""


@dataclass
class GrantCheckResult:
    valid:      bool
    grant_id:   str
    principal:  str
    permission: str
    resource:   str
    expires_at: str
    reason:     str


@dataclass
class ExpiryAlert:
    grant_id:      str
    principal:     str
    permission:    str
    expires_at:    str
    minutes_remaining: int
    severity:      str    # "CRITICAL" | "WARNING" | "INFO"


class TimeBoundAccessManager:
    """
    Manages time-bound access grants for ML infrastructure.

    Parameters
    ----------
    warn_minutes  : Produce expiry alert when grant expires within this many minutes.
    audit_path    : Optional JSON Lines audit log path.
    """

    def __init__(
        self,
        warn_minutes: int = 60,
        audit_path:   Optional[str | Path] = None,
    ):
        self._grants:      Dict[str, TimeBoundGrant] = {}
        self._warn_mins    = warn_minutes
        self._audit        = Path(audit_path) if audit_path else None

    # ── Grant management ──────────────────────────────────────────────────────

    def grant(
        self,
        principal:  str,
        permission: str,
        granted_by: str,
        ttl_seconds: int,
        resource:   str = "*",
        reason:     str = "",
    ) -> TimeBoundGrant:
        """Create a time-bound access grant."""
        now     = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        grant   = TimeBoundGrant(
            grant_id   = str(uuid.uuid4()),
            principal  = principal,
            permission = permission,
            resource   = resource,
            granted_by = granted_by,
            granted_at = now.isoformat(),
            expires_at = expires.isoformat(),
            reason     = reason,
        )
        self._grants[grant.grant_id] = grant
        self._audit_event("grant_created", grant_id=grant.grant_id,
                          principal=principal, permission=permission,
                          resource=resource, expires_at=grant.expires_at,
                          reason=reason, granted_by=granted_by)
        return grant

    def revoke(self, grant_id: str, revoked_by: str = "") -> bool:
        """Immediately revoke a grant. Returns True if found and revoked."""
        grant = self._grants.get(grant_id)
        if grant is None:
            return False
        grant.revoked    = True
        grant.revoked_at = datetime.now(timezone.utc).isoformat()
        grant.revoked_by = revoked_by
        self._audit_event("grant_revoked", grant_id=grant_id,
                          principal=grant.principal, permission=grant.permission,
                          revoked_by=revoked_by)
        return True

    def check(
        self,
        principal:  str,
        permission: str,
        resource:   str = "*",
        now:        Optional[datetime] = None,
    ) -> GrantCheckResult:
        """Check whether a valid time-bound grant exists for this access."""
        now = now or datetime.now(timezone.utc)

        for grant in self._grants.values():
            if grant.principal  != principal:
                continue
            if grant.permission != permission:
                continue
            if grant.resource not in ("*", resource) and resource != "*":
                continue
            if grant.revoked:
                continue

            exp = datetime.fromisoformat(grant.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now > exp:
                continue

            self._audit_event("grant_used", grant_id=grant.grant_id,
                              principal=principal, permission=permission,
                              resource=resource)
            return GrantCheckResult(
                valid      = True,
                grant_id   = grant.grant_id,
                principal  = principal,
                permission = permission,
                resource   = resource,
                expires_at = grant.expires_at,
                reason     = "Valid time-bound grant found",
            )

        return GrantCheckResult(
            valid=False, grant_id="", principal=principal,
            permission=permission, resource=resource, expires_at="",
            reason="No valid time-bound grant found",
        )

    def near_expiry_alerts(self, now: Optional[datetime] = None) -> List[ExpiryAlert]:
        """Return alerts for grants expiring within warn_minutes."""
        now   = now or datetime.now(timezone.utc)
        alerts = []
        for grant in self._grants.values():
            if grant.revoked:
                continue
            exp = datetime.fromisoformat(grant.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now > exp:
                continue
            mins_rem = int((exp - now).total_seconds() / 60)
            if mins_rem <= self._warn_mins:
                if mins_rem <= 5:
                    severity = "CRITICAL"
                elif mins_rem <= 15:
                    severity = "WARNING"
                else:
                    severity = "INFO"
                alerts.append(ExpiryAlert(
                    grant_id       = grant.grant_id,
                    principal      = grant.principal,
                    permission     = grant.permission,
                    expires_at     = grant.expires_at,
                    minutes_remaining = mins_rem,
                    severity       = severity,
                ))
        return sorted(alerts, key=lambda a: a.minutes_remaining)

    def cleanup_expired(self, now: Optional[datetime] = None) -> int:
        """Remove expired (and non-revoked) grants. Returns count removed."""
        now  = now or datetime.now(timezone.utc)
        to_remove = []
        for gid, grant in self._grants.items():
            exp = datetime.fromisoformat(grant.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now > exp:
                to_remove.append(gid)
        for gid in to_remove:
            del self._grants[gid]
        return len(to_remove)

    def active_grants(self, now: Optional[datetime] = None) -> List[TimeBoundGrant]:
        """Return all currently valid (non-expired, non-revoked) grants."""
        now = now or datetime.now(timezone.utc)
        result = []
        for grant in self._grants.values():
            if grant.revoked:
                continue
            exp = datetime.fromisoformat(grant.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now <= exp:
                result.append(grant)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _audit_event(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {
            "ts":    datetime.now(timezone.utc).isoformat(),
            "event": event,
            **kwargs,
        }
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
