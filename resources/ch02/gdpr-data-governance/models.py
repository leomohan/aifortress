"""
models.py  —  Shared dataclasses for AI Fortress data governance
AI Fortress · Chapter 2 · Code Sample 2.A
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


class LegalBasis(str, Enum):
    """GDPR Article 6 lawful bases (+ Art.9 for special categories)."""
    CONSENT                  = "consent"               # Art.6(1)(a) / Art.9(2)(a)
    CONTRACT                 = "contract"               # Art.6(1)(b)
    LEGAL_OBLIGATION         = "legal_obligation"       # Art.6(1)(c)
    VITAL_INTERESTS          = "vital_interests"        # Art.6(1)(d)
    PUBLIC_TASK              = "public_task"            # Art.6(1)(e)
    LEGITIMATE_INTERESTS     = "legitimate_interests"   # Art.6(1)(f)
    # HIPAA
    HIPAA_TREATMENT          = "hipaa_treatment"
    HIPAA_PAYMENT            = "hipaa_payment"
    HIPAA_OPERATIONS         = "hipaa_operations"
    HIPAA_AUTHORIZATION      = "hipaa_authorization"
    # CCPA
    CCPA_BUSINESS_PURPOSE    = "ccpa_business_purpose"


class DSRType(str, Enum):
    ACCESS      = "access"       # GDPR Art.15 / CCPA right-to-know
    ERASURE     = "erasure"      # GDPR Art.17 / CCPA delete
    PORTABILITY = "portability"  # GDPR Art.20
    RECTIFICATION = "rectification"  # GDPR Art.16
    RESTRICTION = "restriction"  # GDPR Art.18
    OBJECTION   = "objection"    # GDPR Art.21


class DSRStatus(str, Enum):
    SUBMITTED   = "submitted"
    IN_PROGRESS = "in_progress"
    COMPLETED   = "completed"
    REJECTED    = "rejected"   # with documented reason
    EXTENDED    = "extended"   # 30-day extension invoked (GDPR Art.12(3))


class TransferMechanism(str, Enum):
    ADEQUACY_DECISION = "adequacy_decision"   # GDPR Art.45
    SCC               = "scc"                 # Standard Contractual Clauses Art.46(2)(c)
    BCR               = "bcr"                 # Binding Corporate Rules Art.47
    DEROGATION        = "derogation"          # Art.49 (explicit consent / vital interests)
    HIPAA_BAA         = "hipaa_baa"           # HIPAA Business Associate Agreement


@dataclass
class DatasetRecord:
    dataset_id:       str
    name:             str
    legal_basis:      LegalBasis
    purpose:          str
    data_categories:  List[str]          # e.g. ["name","email","ip_address"]
    special_categories: List[str]        # GDPR Art.9 special categories
    controller:       str
    processor:        str
    retention_days:   int
    registered_at:    str = ""
    notes:            str = ""

    def __post_init__(self):
        if not self.registered_at:
            self.registered_at = datetime.now(timezone.utc).isoformat()


@dataclass
class ConsentRecord:
    consent_id:   str
    subject_id:   str
    dataset_id:   str
    purpose:      str
    granted_at:   str
    expires_at:   str = ""    # "" = no expiry
    withdrawn_at: str = ""    # "" = not withdrawn
    evidence_ref: str = ""    # link to consent capture record

    @property
    def is_active(self) -> bool:
        if self.withdrawn_at:
            return False
        if self.expires_at:
            return datetime.fromisoformat(self.expires_at) > datetime.now(timezone.utc)
        return True


@dataclass
class DSRRequest:
    request_id:   str
    subject_id:   str
    dsr_type:     DSRType
    regulation:   str            # "GDPR" | "CCPA" | "HIPAA"
    status:       DSRStatus
    submitted_at: str
    sla_deadline: str            # 30 days (GDPR) / 45 days (CCPA)
    completed_at: str = ""
    rejection_reason: str = ""
    datasets_affected: List[str] = field(default_factory=list)
    notes:        str = ""


@dataclass
class RetentionPolicy:
    policy_id:      str
    dataset_id:     str
    data_category:  str
    retention_days: int
    legal_basis:    str          # citation, e.g. "GDPR Art.17(3)(b)"
    review_date:    str
    created_at:     str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
