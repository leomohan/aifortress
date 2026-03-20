"""
risk_bias_documenter.py  —  Risk tier and bias findings documentation
AI Fortress · Chapter 12 · Code Sample 12.B

Structures known limitations, bias findings, and regulatory risk
classification for inclusion in a model card.

EU AI Act risk tiers:
  unacceptable — prohibited (e.g. social scoring, real-time biometric)
  high         — requires conformity assessment (credit, hiring, law enforcement)
  limited      — transparency obligations (chatbots, deep-fake disclosure)
  minimal      — no specific requirements (spam filters, AI games)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


_EU_AI_ACT_TIERS = {"unacceptable", "high", "limited", "minimal"}


@dataclass
class BiasFinding:
    dimension:    str        # e.g. "gender", "age", "geography"
    description:  str
    severity:     str        # "critical" | "moderate" | "low"
    mitigation:   str = ""
    evidence_url: str = ""


@dataclass
class RiskBiasDocument:
    eu_ai_act_tier:    str
    eu_ai_act_reason:  str
    known_limitations: List[str]
    ood_failure_modes: List[str]      # out-of-distribution failure modes
    bias_findings:     List[BiasFinding]
    human_oversight:   str = ""       # description of required human oversight
    additional_risks:  List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


class RiskBiasDocumenter:
    """
    Builds structured risk and bias documentation for a model card.
    """

    def build(
        self,
        eu_ai_act_tier:    str,
        eu_ai_act_reason:  str,
        known_limitations: Optional[List[str]] = None,
        ood_failure_modes: Optional[List[str]] = None,
        bias_findings:     Optional[List[dict]] = None,
        human_oversight:   str = "",
        additional_risks:  Optional[List[str]] = None,
    ) -> RiskBiasDocument:
        if eu_ai_act_tier not in _EU_AI_ACT_TIERS:
            raise ValueError(
                f"Invalid EU AI Act tier '{eu_ai_act_tier}'. "
                f"Must be one of: {sorted(_EU_AI_ACT_TIERS)}"
            )
        findings = []
        for bf in (bias_findings or []):
            if isinstance(bf, dict):
                findings.append(BiasFinding(**bf))
            elif isinstance(bf, BiasFinding):
                findings.append(bf)

        return RiskBiasDocument(
            eu_ai_act_tier    = eu_ai_act_tier,
            eu_ai_act_reason  = eu_ai_act_reason,
            known_limitations = known_limitations or [],
            ood_failure_modes = ood_failure_modes or [],
            bias_findings     = findings,
            human_oversight   = human_oversight,
            additional_risks  = additional_risks or [],
        )

    def validate(self, doc: RiskBiasDocument) -> List[str]:
        """Return list of validation warnings."""
        issues = []
        if not doc.known_limitations:
            issues.append("No known limitations documented.")
        if doc.eu_ai_act_tier == "high" and not doc.human_oversight:
            issues.append("High-risk AI system must document human oversight requirements.")
        if doc.eu_ai_act_tier in ("high", "unacceptable") and not doc.bias_findings:
            issues.append("High-risk AI system should document bias findings.")
        return issues
