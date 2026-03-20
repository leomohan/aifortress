"""
stale_entitlement_detector.py  —  Stale entitlement detection for ML access reviews
AI Fortress · Chapter 11 · Code Sample 11.C

Identifies access entitlements that have not been exercised within a
configurable lookback window, and flags over-privileged accounts relative
to their recorded usage pattern.

Stale criteria:
  STALE    — no activity recorded in the last `lookback_days` days
  DORMANT  — no activity ever recorded (never used since grant)
  RISKY    — stale AND has high-privilege permissions

Recommended actions:
  REVOKE   — stale + high-privilege or dormant
  REVIEW   — stale + low-privilege
  RETAIN   — active within lookback window
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set


_HIGH_PRIVILEGE_PERMS = {
    "model:deploy", "model:delete", "data:write",
    "pipeline:execute", "registry:write", "infra:manage",
    "secrets:read", "cluster:admin", "registry:admin",
    "data:admin", "model:promote",
}


@dataclass
class EntitlementRecord:
    principal:    str
    permissions:  Set[str]
    last_used_at: str         # ISO8601 or "" if never used
    granted_at:   str
    team:         str = ""
    account_type: str = "human"  # "human" | "service"


@dataclass
class StaleEntitlementFinding:
    principal:     str
    status:        str          # "STALE" | "DORMANT" | "ACTIVE"
    risk:          str          # "RISKY" | "LOW" | "OK"
    recommendation: str         # "REVOKE" | "REVIEW" | "RETAIN"
    days_inactive:  int
    high_priv_perms: List[str]
    detail:        str


@dataclass
class StaleEntitlementReport:
    total:       int
    stale:       int
    dormant:     int
    active:      int
    risky:       int
    to_revoke:   int
    to_review:   int
    findings:    List[StaleEntitlementFinding]
    generated_at: str

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        return (
            f"Stale entitlement scan: {self.total} entitlements — "
            f"{self.stale} stale, {self.dormant} dormant, {self.risky} risky. "
            f"Recommended: {self.to_revoke} revoke, {self.to_review} review."
        )


class StaleEntitlementDetector:
    """
    Detects stale and over-privileged entitlements.

    Parameters
    ----------
    lookback_days : Inactivity threshold in days (default 90).
    """

    def __init__(self, lookback_days: int = 90):
        self._lookback = lookback_days

    def scan(
        self,
        entitlements: List[EntitlementRecord],
        now:          Optional[datetime] = None,
    ) -> StaleEntitlementReport:
        now      = now or datetime.now(timezone.utc)
        cutoff   = now - timedelta(days=self._lookback)
        findings: List[StaleEntitlementFinding] = []

        for ent in entitlements:
            finding = self._evaluate(ent, cutoff, now)
            findings.append(finding)

        stale   = sum(1 for f in findings if f.status == "STALE")
        dormant = sum(1 for f in findings if f.status == "DORMANT")
        active  = sum(1 for f in findings if f.status == "ACTIVE")
        risky   = sum(1 for f in findings if f.risk   == "RISKY")
        revoke  = sum(1 for f in findings if f.recommendation == "REVOKE")
        review  = sum(1 for f in findings if f.recommendation == "REVIEW")

        return StaleEntitlementReport(
            total        = len(findings),
            stale        = stale,
            dormant      = dormant,
            active       = active,
            risky        = risky,
            to_revoke    = revoke,
            to_review    = review,
            findings     = findings,
            generated_at = now.isoformat(),
        )

    def _evaluate(
        self,
        ent:    EntitlementRecord,
        cutoff: datetime,
        now:    datetime,
    ) -> StaleEntitlementFinding:
        high_priv = sorted(ent.permissions & _HIGH_PRIVILEGE_PERMS)

        if not ent.last_used_at:
            status = "DORMANT"
            days_inactive = (now - datetime.fromisoformat(
                ent.granted_at).replace(tzinfo=timezone.utc)
            ).days
        else:
            last = datetime.fromisoformat(ent.last_used_at)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            days_inactive = (now - last).days
            status = "STALE" if last < cutoff else "ACTIVE"

        risk = "RISKY" if (status in ("STALE", "DORMANT") and high_priv) else \
               "LOW"   if  status in ("STALE", "DORMANT") else "OK"

        if risk == "RISKY" or status == "DORMANT":
            recommendation = "REVOKE"
        elif status == "STALE":
            recommendation = "REVIEW"
        else:
            recommendation = "RETAIN"

        return StaleEntitlementFinding(
            principal        = ent.principal,
            status           = status,
            risk             = risk,
            recommendation   = recommendation,
            days_inactive    = days_inactive,
            high_priv_perms  = high_priv,
            detail           = (
                f"{ent.principal} ({ent.account_type}): {status} "
                f"for {days_inactive} days. "
                f"{len(high_priv)} high-priv permissions. → {recommendation}"
            ),
        )
