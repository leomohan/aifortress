"""
notification_drafter.py  —  Regulatory notification drafter
AI Fortress · Chapter 17 · Code Sample 17.B

Drafts structured regulatory notifications from incident data.
Outputs a draft notification document for each triggered obligation.
Legal review is always required before submission.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from obligation_checker import NotificationObligation


@dataclass
class NotificationDraft:
    obligation_id:   str
    regulation:      str
    regulator:       str
    draft_text:      str
    required_fields: Dict[str, str]    # field → status ("populated"|"required"|"optional")
    legal_review:    bool = False
    submitted:       bool = False


class NotificationDrafter:
    """
    Drafts regulatory notifications for each triggered obligation.

    Parameters
    ----------
    organisation   : Notifying organisation name.
    dpo_contact    : DPO or privacy officer contact details.
    """

    def __init__(self, organisation: str, dpo_contact: str):
        self._org = organisation
        self._dpo = dpo_contact

    def draft(
        self,
        obligation:          NotificationObligation,
        incident_summary:    str,
        discovery_timestamp: str,
        affected_data_types: List[str],
        affected_count:      Optional[int],
        mitigations_taken:   List[str],
    ) -> NotificationDraft:
        """Generate a draft notification for a specific obligation."""
        import uuid

        now  = datetime.now(timezone.utc).isoformat()
        text = self._body(
            obligation, incident_summary, discovery_timestamp,
            affected_data_types, affected_count, mitigations_taken,
        )
        fields = {
            "Organisation name":    "populated",
            "DPO contact":          "populated",
            "Incident description": "populated" if incident_summary else "required",
            "Discovery timestamp":  "populated" if discovery_timestamp else "required",
            "Affected data types":  "populated" if affected_data_types else "required",
            "Affected count":       "populated" if affected_count else "optional",
            "Likely consequences":  "required",
            "Measures taken":       "populated" if mitigations_taken else "required",
            "Legal review sign-off": "required",
        }
        return NotificationDraft(
            obligation_id  = str(uuid.uuid4())[:8],
            regulation     = obligation.regulation,
            regulator      = obligation.regulator,
            draft_text     = text,
            required_fields = fields,
        )

    def _body(
        self,
        ob:               NotificationObligation,
        summary:          str,
        discovery_ts:     str,
        data_types:       List[str],
        count:            Optional[int],
        mitigations:      List[str],
    ) -> str:
        count_str = str(count) if count else "[TO BE DETERMINED]"
        mit_list  = "\n".join(f"  - {m}" for m in mitigations) if mitigations else "  [TO BE COMPLETED]"
        types_str = ", ".join(data_types) if data_types else "[TO BE COMPLETED]"

        return f"""
DRAFT REGULATORY NOTIFICATION — {ob.regulation}
{'=' * 60}
[LEGAL REVIEW REQUIRED BEFORE SUBMISSION]
Drafted: {datetime.now(timezone.utc).isoformat()}

TO:      {ob.regulator}
FROM:    {self._org}
RE:      Notification of Security Incident

---

1. NOTIFYING ORGANISATION
   Name:     {self._org}
   Contact:  {self._dpo}

2. INCIDENT DESCRIPTION
   {summary if summary else '[DESCRIBE INCIDENT]'}

3. DATE/TIME OF DISCOVERY
   {discovery_ts if discovery_ts else '[INSERT TIMESTAMP]'}

4. NATURE OF INCIDENT
   Categories of personal data affected: {types_str}
   Approximate number of individuals affected: {count_str}

5. LIKELY CONSEQUENCES
   [DESCRIBE LIKELY CONSEQUENCES — e.g. identity theft, financial loss,
    reputational harm, discrimination, loss of confidentiality]

6. MEASURES TAKEN OR PROPOSED
{mit_list}

7. LEGAL BASIS FOR NOTIFICATION
   This notification is made pursuant to {ob.regulation}.
   {ob.notes}

---
⚠️  DRAFT — NOT FOR SUBMISSION WITHOUT LEGAL REVIEW
    Required fields marked as 'required' in accompanying field checklist
    must be completed before submission.
""".strip()
