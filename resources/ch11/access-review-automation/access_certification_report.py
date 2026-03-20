"""
access_certification_report.py  —  Access certification compliance report
AI Fortress · Chapter 11 · Code Sample 11.C

Produces a structured access certification report from a completed (or
in-progress) review campaign, suitable for audit evidence submission.

Report sections:
  - Campaign metadata (name, period, owner, status)
  - Summary statistics (total, certified, revoked, pending, completion %)
  - Remediation list (principals and permissions to revoke)
  - Reviewer participation (decisions per reviewer)
  - Risk summary (high-privilege entitlements certified/revoked)
  - Sign-off block (sign-off principal + timestamp)
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from review_workflow import ReviewCampaign, ReviewItem, ReviewWorkflowEngine


_HIGH_PRIV = {
    "model:deploy", "model:delete", "data:write",
    "pipeline:execute", "registry:write", "infra:manage",
    "secrets:read", "cluster:admin", "data:admin", "model:promote",
}


@dataclass
class RemediationEntry:
    principal:   str
    permissions: List[str]
    team:        str
    decided_by:  str
    reason:      str


@dataclass
class ReviewerStats:
    reviewer:   str
    assigned:   int
    decided:    int
    certified:  int
    revoked:    int
    pending:    int


@dataclass
class CertificationReport:
    report_id:         str
    campaign_id:       str
    campaign_name:     str
    campaign_status:   str
    review_period_start: str
    review_period_end:   str
    generated_at:      str
    generated_by:      str

    total_entitlements: int
    certified:          int
    revoked:            int
    pending:            int
    completion_pct:     float

    remediation_list:   List[RemediationEntry]
    reviewer_stats:     List[ReviewerStats]
    high_priv_certified: int
    high_priv_revoked:   int

    signed_off_by:      str = ""
    signed_off_at:      str = ""
    sign_off_notes:     str = ""

    def sign_off(self, principal: str, notes: str = "") -> None:
        self.signed_off_by  = principal
        self.signed_off_at  = datetime.now(timezone.utc).isoformat()
        self.sign_off_notes = notes

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        status_icon = "✅" if self.completion_pct == 100.0 else "⚠️"
        return (
            f"{status_icon} Certification report '{self.campaign_name}': "
            f"{self.completion_pct:.1f}% complete — "
            f"{self.certified} certified, {self.revoked} revoked, "
            f"{self.pending} pending. "
            f"Remediation: {len(self.remediation_list)} entitlements."
        )


class AccessCertificationReporter:
    """
    Generates access certification compliance reports.
    """

    def generate(
        self,
        campaign:     ReviewCampaign,
        generated_by: str,
    ) -> CertificationReport:
        total     = len(campaign.items)
        certified = sum(1 for i in campaign.items if i.decision == "certify")
        revoked   = sum(1 for i in campaign.items if i.decision == "revoke")
        pending   = sum(1 for i in campaign.items if not i.decision)
        pct       = round(certified + revoked) / total * 100 if total else 0.0

        remediation = self._build_remediation(campaign.items)
        reviewer_stats = self._reviewer_stats(campaign.items)

        high_priv_cert  = sum(
            1 for i in campaign.items
            if i.decision == "certify" and any(p in _HIGH_PRIV for p in i.permissions)
        )
        high_priv_rev   = sum(
            1 for i in campaign.items
            if i.decision == "revoke" and any(p in _HIGH_PRIV for p in i.permissions)
        )

        return CertificationReport(
            report_id              = str(uuid.uuid4()),
            campaign_id            = campaign.campaign_id,
            campaign_name          = campaign.name,
            campaign_status        = campaign.status,
            review_period_start    = campaign.created_at,
            review_period_end      = campaign.closed_at or datetime.now(timezone.utc).isoformat(),
            generated_at           = datetime.now(timezone.utc).isoformat(),
            generated_by           = generated_by,
            total_entitlements     = total,
            certified              = certified,
            revoked                = revoked,
            pending                = pending,
            completion_pct         = pct,
            remediation_list       = remediation,
            reviewer_stats         = reviewer_stats,
            high_priv_certified    = high_priv_cert,
            high_priv_revoked      = high_priv_rev,
        )

    @staticmethod
    def _build_remediation(items: List[ReviewItem]) -> List[RemediationEntry]:
        return [
            RemediationEntry(
                principal   = i.principal,
                permissions = i.permissions,
                team        = i.team,
                decided_by  = i.reviewer,
                reason      = i.decision_reason,
            )
            for i in items if i.decision == "revoke"
        ]

    @staticmethod
    def _reviewer_stats(items: List[ReviewItem]) -> List[ReviewerStats]:
        stats: Dict[str, ReviewerStats] = {}
        for item in items:
            rv = item.reviewer or "unassigned"
            if rv not in stats:
                stats[rv] = ReviewerStats(
                    reviewer=rv, assigned=0, decided=0,
                    certified=0, revoked=0, pending=0,
                )
            s = stats[rv]
            s.assigned += 1
            if item.decision == "certify":
                s.decided   += 1
                s.certified += 1
            elif item.decision == "revoke":
                s.decided += 1
                s.revoked += 1
            else:
                s.pending += 1
        return list(stats.values())
