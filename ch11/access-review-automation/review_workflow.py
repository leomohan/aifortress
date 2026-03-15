"""
review_workflow.py  —  Access review campaign workflow engine
AI Fortress · Chapter 11 · Code Sample 11.C

Manages the full access review campaign lifecycle:
  1. CREATE   — create a campaign with a list of entitlements to review
  2. ASSIGN   — assign reviewer(s) to each entitlement
  3. DECIDE   — reviewer records CERTIFY or REVOKE decision per entitlement
  4. ESCALATE — entitlements without a decision past deadline are escalated
  5. CLOSE    — campaign is closed; remediation list generated

Campaign status states:
  open → in_progress → closed | escalated
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ReviewItem:
    item_id:     str
    principal:   str
    permissions: List[str]
    team:        str
    reviewer:    str = ""
    decision:    str = ""        # "" | "certify" | "revoke"
    decided_at:  str = ""
    decision_reason: str = ""
    escalated:   bool = False


@dataclass
class ReviewCampaign:
    campaign_id:  str
    name:         str
    created_at:   str
    deadline:     str
    created_by:   str
    status:       str = "open"   # open | in_progress | closed | escalated
    items:        List[ReviewItem] = field(default_factory=list)
    closed_at:    str = ""


@dataclass
class CampaignProgress:
    campaign_id:  str
    total:        int
    decided:      int
    certified:    int
    revoked:      int
    pending:      int
    completion_pct: float
    is_overdue:   bool


class ReviewWorkflowEngine:
    """
    Manages access review campaign workflows.

    Parameters
    ----------
    audit_path : Optional JSON Lines path for workflow events.
    """

    def __init__(self, audit_path: Optional[str | Path] = None):
        self._campaigns: Dict[str, ReviewCampaign] = {}
        self._audit = Path(audit_path) if audit_path else None

    def create_campaign(
        self,
        name:          str,
        entitlements:  List[dict],   # list of {principal, permissions, team}
        created_by:    str,
        deadline_days: int = 14,
    ) -> ReviewCampaign:
        """Create a new review campaign from a list of entitlements."""
        now      = datetime.now(timezone.utc)
        deadline = (now + timedelta(days=deadline_days)).isoformat()
        campaign = ReviewCampaign(
            campaign_id = str(uuid.uuid4()),
            name        = name,
            created_at  = now.isoformat(),
            deadline    = deadline,
            created_by  = created_by,
            items       = [
                ReviewItem(
                    item_id     = str(uuid.uuid4()),
                    principal   = e["principal"],
                    permissions = e.get("permissions", []),
                    team        = e.get("team", ""),
                )
                for e in entitlements
            ],
        )
        self._campaigns[campaign.campaign_id] = campaign
        self._log("campaign_created", campaign_id=campaign.campaign_id,
                  name=name, items=len(campaign.items), created_by=created_by)
        return campaign

    def assign_reviewer(
        self,
        campaign_id: str,
        item_id:     str,
        reviewer:    str,
    ) -> bool:
        """Assign a reviewer to a specific review item."""
        item = self._get_item(campaign_id, item_id)
        if item is None:
            return False
        item.reviewer = reviewer
        campaign = self._campaigns[campaign_id]
        if campaign.status == "open":
            campaign.status = "in_progress"
        return True

    def assign_all(
        self,
        campaign_id: str,
        reviewer_map: Dict[str, str],   # team → reviewer
        default_reviewer: str = "",
    ) -> int:
        """Assign reviewers to all items using a team→reviewer map."""
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            return 0
        assigned = 0
        for item in campaign.items:
            reviewer = reviewer_map.get(item.team, default_reviewer)
            if reviewer:
                item.reviewer = reviewer
                assigned += 1
        if assigned and campaign.status == "open":
            campaign.status = "in_progress"
        return assigned

    def record_decision(
        self,
        campaign_id: str,
        item_id:     str,
        decision:    str,
        reviewer:    str,
        reason:      str = "",
    ) -> bool:
        """Record a CERTIFY or REVOKE decision for a review item."""
        if decision not in ("certify", "revoke"):
            raise ValueError(f"Decision must be 'certify' or 'revoke', got '{decision}'")
        item = self._get_item(campaign_id, item_id)
        if item is None:
            return False
        item.decision        = decision
        item.decided_at      = datetime.now(timezone.utc).isoformat()
        item.decision_reason = reason
        self._log("decision_recorded", campaign_id=campaign_id, item_id=item_id,
                  principal=item.principal, decision=decision, reviewer=reviewer)
        return True

    def escalate_overdue(
        self,
        campaign_id: str,
        now:         Optional[datetime] = None,
    ) -> List[ReviewItem]:
        """Mark unanswered items as escalated if campaign is past deadline."""
        now      = now or datetime.now(timezone.utc)
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            return []
        deadline = datetime.fromisoformat(campaign.deadline)
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        if now <= deadline:
            return []
        escalated = []
        for item in campaign.items:
            if not item.decision:
                item.escalated = True
                escalated.append(item)
        if escalated:
            campaign.status = "escalated"
        self._log("campaign_escalated", campaign_id=campaign_id,
                  escalated_count=len(escalated))
        return escalated

    def close_campaign(self, campaign_id: str) -> List[ReviewItem]:
        """Close a campaign and return the list of items recommended for revocation."""
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            raise KeyError(f"Campaign '{campaign_id}' not found")
        campaign.status    = "closed"
        campaign.closed_at = datetime.now(timezone.utc).isoformat()
        to_revoke = [i for i in campaign.items if i.decision == "revoke"]
        self._log("campaign_closed", campaign_id=campaign_id,
                  to_revoke=len(to_revoke))
        return to_revoke

    def progress(
        self,
        campaign_id: str,
        now:         Optional[datetime] = None,
    ) -> CampaignProgress:
        now      = now or datetime.now(timezone.utc)
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            raise KeyError(f"Campaign '{campaign_id}' not found")
        total     = len(campaign.items)
        decided   = sum(1 for i in campaign.items if i.decision)
        certified = sum(1 for i in campaign.items if i.decision == "certify")
        revoked   = sum(1 for i in campaign.items if i.decision == "revoke")
        pending   = total - decided
        deadline  = datetime.fromisoformat(campaign.deadline)
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        return CampaignProgress(
            campaign_id    = campaign_id,
            total          = total,
            decided        = decided,
            certified      = certified,
            revoked        = revoked,
            pending        = pending,
            completion_pct = round(decided / total * 100, 1) if total else 0.0,
            is_overdue     = now > deadline,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get_item(self, campaign_id: str, item_id: str) -> Optional[ReviewItem]:
        campaign = self._campaigns.get(campaign_id)
        if campaign is None:
            return None
        for item in campaign.items:
            if item.item_id == item_id:
                return item
        return None

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
