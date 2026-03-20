"""
control_registry.py  —  Regulation-to-control mapping registry
AI Fortress · Chapter 2 · Code Sample 2.C

Maps GDPR, CCPA, HIPAA, and EU AI Act articles to specific technical and
organisational controls that an ML system must implement.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class ControlStatus(str, Enum):
    COMPLIANT = "compliant"
    PARTIAL   = "partial"
    GAP       = "gap"
    NA        = "not_applicable"


class ControlCategory(str, Enum):
    TECHNICAL      = "technical"
    ORGANISATIONAL = "organisational"
    LEGAL          = "legal"


@dataclass
class Control:
    control_id:   str
    regulation:   str
    article:      str       # e.g. "Art.5(1)(f)", "45 CFR 164.312(a)"
    title:        str
    description:  str
    category:     ControlCategory
    evidence_keys: List[str]   # which evidence keys satisfy this control


# Full control registry — GDPR, CCPA, HIPAA, EU AI Act
CONTROLS: List[Control] = [

    # ── GDPR ──────────────────────────────────────────────────────────────────
    Control("GDPR-01", "GDPR", "Art.5(1)(b)", "Purpose Limitation",
            "Personal data collected for specified, explicit, legitimate purposes; not further processed incompatibly.",
            ControlCategory.LEGAL, ["lawful_basis_registered", "purpose_documented"]),
    Control("GDPR-02", "GDPR", "Art.5(1)(c)", "Data Minimisation",
            "Personal data adequate, relevant, limited to what is necessary.",
            ControlCategory.ORGANISATIONAL, ["data_categories_documented", "minimisation_review"]),
    Control("GDPR-03", "GDPR", "Art.5(1)(e)", "Storage Limitation",
            "Personal data kept no longer than necessary; retention policy in place.",
            ControlCategory.TECHNICAL, ["retention_policy_declared", "deletion_certificates_present"]),
    Control("GDPR-04", "GDPR", "Art.5(1)(f)", "Integrity & Confidentiality",
            "Appropriate technical measures to ensure security of personal data.",
            ControlCategory.TECHNICAL, ["encryption_at_rest", "access_controls_documented"]),
    Control("GDPR-05", "GDPR", "Art.6",   "Lawful Basis Documented",
            "A valid legal basis is identified and documented for each processing activity.",
            ControlCategory.LEGAL, ["lawful_basis_registered"]),
    Control("GDPR-06", "GDPR", "Art.13/14", "Transparency",
            "Data subjects informed of processing at collection time.",
            ControlCategory.LEGAL, ["privacy_notice_present"]),
    Control("GDPR-07", "GDPR", "Art.17",  "Right to Erasure",
            "Erasure requests can be fulfilled within 30 days; DSR workflow operational.",
            ControlCategory.TECHNICAL, ["dsr_workflow_operational", "erasure_sla_met"]),
    Control("GDPR-08", "GDPR", "Art.25",  "Privacy by Design",
            "Data protection by design and default; pseudonymisation and data minimisation implemented.",
            ControlCategory.TECHNICAL, ["pseudonymisation_applied", "minimisation_review"]),
    Control("GDPR-09", "GDPR", "Art.30",  "Records of Processing Activities",
            "Maintain written RoPA for all processing activities.",
            ControlCategory.ORGANISATIONAL, ["ropa_current"]),
    Control("GDPR-10", "GDPR", "Art.35",  "DPIA Conducted",
            "Data Protection Impact Assessment completed for high-risk processing.",
            ControlCategory.ORGANISATIONAL, ["dpia_completed"]),
    Control("GDPR-11", "GDPR", "Art.44-49", "Cross-border Transfers",
            "Adequate safeguards for transfers outside EEA (SCCs, BCRs, adequacy decisions).",
            ControlCategory.LEGAL, ["transfer_controls_documented"]),

    # ── CCPA / CPRA ───────────────────────────────────────────────────────────
    Control("CCPA-01", "CCPA", "§1798.100", "Right to Know",
            "Consumers can request disclosure of personal information categories collected.",
            ControlCategory.LEGAL, ["data_categories_documented", "dsr_workflow_operational"]),
    Control("CCPA-02", "CCPA", "§1798.105", "Right to Delete",
            "Consumers can request deletion of personal information; fulfilled within 45 days.",
            ControlCategory.TECHNICAL, ["dsr_workflow_operational", "erasure_sla_met"]),
    Control("CCPA-03", "CCPA", "§1798.120", "Right to Opt-Out",
            "Consumers can opt out of sale/sharing of personal information.",
            ControlCategory.LEGAL, ["opt_out_mechanism_documented"]),
    Control("CCPA-04", "CCPA", "§1798.150", "Reasonable Security",
            "Reasonable security procedures and practices appropriate to data sensitivity.",
            ControlCategory.TECHNICAL, ["encryption_at_rest", "access_controls_documented"]),

    # ── HIPAA ─────────────────────────────────────────────────────────────────
    Control("HIPAA-01", "HIPAA", "164.312(a)(1)", "Access Control",
            "Unique user identification; automatic logoff; encryption/decryption.",
            ControlCategory.TECHNICAL, ["access_controls_documented", "encryption_at_rest"]),
    Control("HIPAA-02", "HIPAA", "164.312(b)",    "Audit Controls",
            "Hardware, software, procedural mechanisms to record and examine activity.",
            ControlCategory.TECHNICAL, ["audit_logs_present"]),
    Control("HIPAA-03", "HIPAA", "164.312(c)(1)", "Integrity Controls",
            "Policies to protect ePHI from improper alteration or destruction.",
            ControlCategory.TECHNICAL, ["integrity_verification_present"]),
    Control("HIPAA-04", "HIPAA", "164.312(e)(2)(ii)", "Encryption in Transit",
            "Encrypt ePHI in transit whenever deemed reasonable and appropriate.",
            ControlCategory.TECHNICAL, ["encryption_in_transit"]),
    Control("HIPAA-05", "HIPAA", "164.308(b)",   "BAA in Place",
            "Business Associate Agreements executed with all processors of ePHI.",
            ControlCategory.LEGAL, ["baa_documented"]),

    # ── EU AI Act ─────────────────────────────────────────────────────────────
    Control("EUAIA-01", "EU_AI_ACT", "Art.10", "Data Governance",
            "Training data governed for relevance, representativeness, errors, completeness.",
            ControlCategory.ORGANISATIONAL, ["data_categories_documented", "ropa_current"]),
    Control("EUAIA-02", "EU_AI_ACT", "Art.13", "Transparency",
            "High-risk AI systems must be sufficiently transparent to enable users to interpret outputs.",
            ControlCategory.ORGANISATIONAL, ["transparency_documentation_present"]),
    Control("EUAIA-03", "EU_AI_ACT", "Art.9",  "Risk Management",
            "Ongoing risk management system throughout lifecycle.",
            ControlCategory.ORGANISATIONAL, ["risk_register_present"]),
]


class ControlRegistry:
    def __init__(self):
        self._controls = {c.control_id: c for c in CONTROLS}

    def all_controls(self) -> List[Control]:
        return list(self._controls.values())

    def for_regulation(self, regulation: str) -> List[Control]:
        return [c for c in self._controls.values() if c.regulation == regulation.upper().replace("-","_")]

    def get(self, control_id: str) -> Control | None:
        return self._controls.get(control_id)
