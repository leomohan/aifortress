"""
obligation_checker.py  —  Regulatory notification obligation checker
AI Fortress · Chapter 17 · Code Sample 17.B

Determines which regulatory notification obligations apply to an
AI security incident based on incident characteristics.

Regulations covered:
  GDPR Art.33/34  — EU personal data breach
  UK GDPR / ICO   — UK personal data breach
  NIS2            — Network and Information Security Directive 2
  EU AI Act Art.73 — Serious incident from high-risk AI system
  HIPAA           — US healthcare PHI breach
  SEC             — US public company material cybersecurity incident
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class NotificationObligation:
    regulation:       str
    regulator:        str
    deadline_hours:   Optional[int]   # None = "without undue delay" / variable
    deadline_label:   str
    recipient:        str             # regulator, individuals, or both
    triggered_by:     List[str]
    mandatory:        bool
    notes:            str


@dataclass
class ObligationCheckResult:
    incident_id:      str
    obligations:      List[NotificationObligation]
    n_mandatory:      int
    earliest_deadline_hours: Optional[int]
    summary:          str


class ObligationChecker:
    """
    Checks regulatory notification obligations for an AI security incident.

    Parameters
    ----------
    jurisdictions : List of applicable jurisdictions
                    (e.g. ["EU", "UK", "US_healthcare", "US_public_company"]).
    """

    _OBLIGATIONS = [
        NotificationObligation(
            regulation="GDPR Art.33", regulator="Supervisory Authority (EU DPA)",
            deadline_hours=72, deadline_label="72 hours from awareness",
            recipient="regulator",
            triggered_by=["personal_data_breach", "eu_residents_affected"],
            mandatory=True,
            notes="Required unless breach is unlikely to result in risk to individuals.",
        ),
        NotificationObligation(
            regulation="GDPR Art.34", regulator="Affected individuals",
            deadline_hours=None, deadline_label="Without undue delay",
            recipient="individuals",
            triggered_by=["personal_data_breach", "high_risk_to_individuals"],
            mandatory=True,
            notes="Required when breach likely results in high risk to individuals.",
        ),
        NotificationObligation(
            regulation="UK GDPR / ICO", regulator="Information Commissioner's Office",
            deadline_hours=72, deadline_label="72 hours",
            recipient="regulator",
            triggered_by=["personal_data_breach", "uk_residents_affected"],
            mandatory=True,
            notes="UK-specific obligation post-Brexit.",
        ),
        NotificationObligation(
            regulation="NIS2 Art.23", regulator="National CSIRT / Competent authority",
            deadline_hours=24, deadline_label="24h early warning; 72h full notification",
            recipient="regulator",
            triggered_by=["significant_incident", "essential_entity_affected"],
            mandatory=True,
            notes="Applies to essential and important entities under NIS2.",
        ),
        NotificationObligation(
            regulation="EU AI Act Art.73", regulator="Market Surveillance Authority",
            deadline_hours=None, deadline_label="15 working days",
            recipient="regulator",
            triggered_by=["serious_incident", "high_risk_ai_affected"],
            mandatory=True,
            notes="Serious incident = death, serious harm, significant property damage, or fundamental rights violation.",
        ),
        NotificationObligation(
            regulation="HIPAA Breach Rule", regulator="HHS OCR + Affected individuals",
            deadline_hours=None, deadline_label="60 days from discovery (individuals); annual if <500",
            recipient="regulator and individuals",
            triggered_by=["phi_breach", "us_healthcare"],
            mandatory=True,
            notes="Breaches affecting >500 residents in a state also require media notification.",
        ),
        NotificationObligation(
            regulation="SEC Rule 10-K/8-K", regulator="SEC + Investors",
            deadline_hours=96, deadline_label="4 business days (material incidents)",
            recipient="regulator",
            triggered_by=["material_incident", "us_public_company"],
            mandatory=True,
            notes="Materiality determined by whether a reasonable investor would find it important.",
        ),
    ]

    def __init__(self, jurisdictions: Optional[List[str]] = None):
        self._jurisdictions = [j.lower() for j in (jurisdictions or [])]

    def check(
        self,
        incident_id:             str,
        personal_data_breach:    bool = False,
        eu_residents_affected:   bool = False,
        uk_residents_affected:   bool = False,
        high_risk_to_individuals:bool = False,
        significant_incident:    bool = False,
        essential_entity:        bool = False,
        serious_incident:        bool = False,
        high_risk_ai:            bool = False,
        phi_breach:              bool = False,
        material_incident:       bool = False,
    ) -> ObligationCheckResult:
        flags = {
            "personal_data_breach":      personal_data_breach,
            "eu_residents_affected":     eu_residents_affected,
            "uk_residents_affected":     uk_residents_affected,
            "high_risk_to_individuals":  high_risk_to_individuals,
            "significant_incident":      significant_incident,
            "essential_entity_affected": essential_entity,
            "serious_incident":          serious_incident,
            "high_risk_ai_affected":     high_risk_ai,
            "phi_breach":                phi_breach,
            "us_healthcare":             phi_breach,
            "material_incident":         material_incident,
            "us_public_company":         material_incident,
        }

        triggered: List[NotificationObligation] = []
        for ob in self._OBLIGATIONS:
            if all(flags.get(t, False) for t in ob.triggered_by):
                triggered.append(ob)

        mandatory = [o for o in triggered if o.mandatory]
        deadlines = [o.deadline_hours for o in mandatory if o.deadline_hours]
        earliest  = min(deadlines) if deadlines else None

        return ObligationCheckResult(
            incident_id              = incident_id,
            obligations              = triggered,
            n_mandatory              = len(mandatory),
            earliest_deadline_hours  = earliest,
            summary = (
                f"{len(triggered)} notification obligation(s) triggered "
                f"({len(mandatory)} mandatory). "
                + (f"Earliest deadline: {earliest}h." if earliest else
                   "Deadline: 'without undue delay' or per regulation.")
            ),
        )
