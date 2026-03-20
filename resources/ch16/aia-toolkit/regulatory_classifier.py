"""
regulatory_classifier.py  —  Regulatory risk classification for AI systems
AI Fortress · Chapter 16 · Code Sample 16.C

Classifies an AI system under the EU AI Act (Annex III high-risk categories)
and relevant sector-specific regulations, and lists the resulting
compliance obligations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


_EU_AI_ACT_HIGH_RISK: Dict[str, List[str]] = {
    "biometric": [
        "Real-time remote biometric identification",
        "Post remote biometric identification",
        "Emotion recognition",
        "Biometric categorisation",
    ],
    "critical_infrastructure": [
        "Safety components of critical infrastructure",
    ],
    "education": [
        "Student assessment and evaluation",
        "Access to educational institutions",
        "Monitoring during exams",
    ],
    "employment": [
        "Recruitment and candidate screening",
        "Work performance monitoring",
        "Promotion/demotion decisions",
        "Task allocation",
    ],
    "essential_services": [
        "Credit scoring",
        "Life/health insurance risk assessment",
        "Social benefits eligibility",
    ],
    "law_enforcement": [
        "Individual risk assessment",
        "Polygraphs and similar tools",
        "Deepfake detection",
        "Crime analytics",
    ],
    "migration": [
        "Asylum application processing",
        "Border crossing risk assessment",
        "Visa and residence permit evaluation",
    ],
    "justice": [
        "Administration of justice",
        "Legal research and interpretation assistance",
    ],
}

_PROHIBITED: List[str] = [
    "Subliminal manipulation",
    "Exploitation of vulnerable groups",
    "Social scoring by public authorities",
    "Real-time remote biometric identification in public spaces (with narrow exceptions)",
]

_OBLIGATIONS: Dict[str, List[str]] = {
    "high_risk": [
        "EU AI Act Art.9: Risk management system",
        "EU AI Act Art.10: High-quality training data (bias-free)",
        "EU AI Act Art.11: Technical documentation",
        "EU AI Act Art.12: Logging and traceability",
        "EU AI Act Art.13: Transparency to users",
        "EU AI Act Art.14: Human oversight mechanisms",
        "EU AI Act Art.15: Accuracy, robustness, and cybersecurity",
        "GDPR Art.22: Right to explanation for automated decisions",
        "Conformity assessment before deployment",
        "EU AI Act Art.49: Post-market monitoring",
    ],
    "limited_risk": [
        "EU AI Act Art.50: Transparency obligations (disclose AI interaction)",
    ],
    "minimal_risk": [
        "Voluntary codes of conduct",
    ],
}


@dataclass
class RegulatoryClassification:
    system_name:      str
    eu_ai_act_tier:   str    # "prohibited"|"high_risk"|"limited_risk"|"minimal_risk"
    matched_categories: List[str]   # Annex III categories matched
    obligations:      List[str]
    sector_flags:     List[str]     # sector-specific regulatory notes
    prohibited:       bool
    summary:          str


class RegulatoryClassifier:
    """Classifies an AI system under EU AI Act and sector regulations."""

    def classify(
        self,
        system_name:    str,
        use_cases:      List[str],   # free-text descriptions of system use cases
        sectors:        Optional[List[str]] = None,
    ) -> RegulatoryClassification:
        """
        Parameters
        ----------
        use_cases : List of system use-case descriptions (checked against Annex III).
        sectors   : Optional list of deployment sectors for additional flags.
        """
        use_lower = [u.lower() for u in use_cases]
        matched:  List[str] = []
        prohibited = False

        # Check prohibited uses
        for p in _PROHIBITED:
            if any(kw in " ".join(use_lower) for kw in p.lower().split()[:3]):
                prohibited = True

        # Check Annex III high-risk categories
        for category, items in _EU_AI_ACT_HIGH_RISK.items():
            for item in items:
                keywords = item.lower().split()[:2]
                if any(all(kw in u for kw in keywords) for u in use_lower):
                    matched.append(f"{category}: {item}")

        if prohibited:
            tier = "prohibited"
        elif matched:
            tier = "high_risk"
        elif any(kw in " ".join(use_lower) for kw in ["chatbot", "ai-generated", "deepfake detection"]):
            tier = "limited_risk"
        else:
            tier = "minimal_risk"

        obligations = _OBLIGATIONS.get(tier, [])
        sector_flags: List[str] = []
        for s in (sectors or []):
            sl = s.lower()
            if "finance" in sl or "credit" in sl:
                sector_flags.append("ECOA / Fair Housing Act: Protected class discrimination prohibited (US)")
            if "health" in sl:
                sector_flags.append("HIPAA: PHI protection and non-discrimination requirements")
            if "eu" in sl or "europe" in sl:
                sector_flags.append("GDPR Art.22: Automated decision-making rights")

        return RegulatoryClassification(
            system_name       = system_name,
            eu_ai_act_tier    = tier,
            matched_categories = matched,
            obligations       = obligations,
            sector_flags      = sector_flags,
            prohibited        = prohibited,
            summary           = (
                f"'{system_name}' classified as EU AI Act {tier.upper()}. "
                f"{len(matched)} Annex III category match(es). "
                f"{len(obligations)} compliance obligation(s)."
            ),
        )
