"""
gap_analyser.py  —  AI security maturity gap analysis and benchmarking
AI Fortress · Chapter 14 · Code Sample 14.B

Analyses maturity gaps in detail, produces prioritised remediation
guidance for each capability, and optionally benchmarks the organisation
against industry reference scores.

Reference benchmarks are illustrative estimates based on published
NIST AI RMF adoption surveys and ISO 42001 assessments (2024–2025).
Replace with actual benchmark data from your industry sector.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from maturity_model import CAPABILITIES
from maturity_scorer import CapabilityScore, MaturityReport


# Illustrative industry benchmarks (mean maturity level by capability and sector)
_BENCHMARKS: Dict[str, Dict[str, float]] = {
    "financial_services": {
        "GOV-01": 3.2, "GOV-02": 2.8, "GOV-03": 2.5,
        "MAP-01": 2.6, "MAP-02": 2.2, "MAP-03": 1.8,
        "MEA-01": 3.1, "MEA-02": 2.4, "MEA-03": 2.0,
        "MAN-01": 2.7, "MAN-02": 2.3, "MAN-03": 2.9, "MAN-04": 1.9,
    },
    "healthcare": {
        "GOV-01": 2.8, "GOV-02": 2.5, "GOV-03": 2.0,
        "MAP-01": 2.3, "MAP-02": 2.4, "MAP-03": 1.5,
        "MEA-01": 2.6, "MEA-02": 2.0, "MEA-03": 2.1,
        "MAN-01": 2.4, "MAN-02": 1.9, "MAN-03": 2.8, "MAN-04": 2.0,
    },
    "technology": {
        "GOV-01": 2.5, "GOV-02": 2.4, "GOV-03": 2.2,
        "MAP-01": 2.8, "MAP-02": 2.0, "MAP-03": 2.3,
        "MEA-01": 3.4, "MEA-02": 2.9, "MEA-03": 2.2,
        "MAN-01": 2.6, "MAN-02": 2.7, "MAN-03": 2.5, "MAN-04": 2.1,
    },
    "cross_sector": {
        "GOV-01": 2.8, "GOV-02": 2.5, "GOV-03": 2.2,
        "MAP-01": 2.5, "MAP-02": 2.0, "MAP-03": 1.8,
        "MEA-01": 2.9, "MEA-02": 2.3, "MEA-03": 1.9,
        "MAN-01": 2.5, "MAN-02": 2.2, "MAN-03": 2.6, "MAN-04": 1.8,
    },
}

_REMEDIATION_GUIDANCE: Dict[str, List[str]] = {
    "GOV-01": [
        "Draft AI Risk Management Policy using NIST AI RMF as template",
        "Obtain CISO and board-level approval",
        "Publish and communicate to all AI project teams",
    ],
    "GOV-02": [
        "Define RACI matrix for AI security roles",
        "Assign named individuals to CISO, ML Security Lead, DPO, AI Ethics Lead",
        "Include AI security accountabilities in job descriptions",
    ],
    "GOV-03": [
        "Establish cross-functional AI Risk Committee with formal ToR",
        "Schedule quarterly meetings with documented minutes",
        "Escalate high-risk AI deployments to committee for approval",
    ],
    "MAP-01": [
        "Create AI system register using SBOM tooling (resource Ch08)",
        "Classify each system by EU AI Act risk tier and data sensitivity",
        "Assign business owner and technical owner per system",
    ],
    "MAP-02": [
        "Adopt AIA policy template (resource Ch16 / Ch14 template)",
        "Make AIA a mandatory deployment gate for high-risk systems",
        "Train project managers on AIA process",
    ],
    "MAP-03": [
        "Adopt STRIDE threat modelling for all new AI system designs",
        "Use edge AI threat model templates (resource Ch15)",
        "Run AI-specific threat intelligence review annually",
    ],
    "MEA-01": [
        "Deploy drift detection dashboard (resource Ch10)",
        "Define SLOs for model accuracy and set alert thresholds",
        "Add fairness parity tracking (resource Ch16)",
    ],
    "MEA-02": [
        "Integrate adversarial robustness tests into CI/CD",
        "Run annual AI red-team exercise",
        "Use physical adversarial eval tools for edge models (resource Ch15)",
    ],
    "MEA-03": [
        "Implement fairness evaluation suite pre-deployment (resource Ch16.A)",
        "Set DPD/EOD thresholds in Fairness Requirements Specification",
        "Deploy production parity monitoring (resource Ch16.D)",
    ],
    "MAN-01": [
        "Develop AI-specific IRP using AI Fortress Ch17 runbook",
        "Run annual tabletop exercise with AI incident scenarios",
        "Track TTD, TTC, TTR metrics and set improvement targets",
    ],
    "MAN-02": [
        "Implement SBOM pipeline for all third-party AI components (resource Ch08)",
        "Assess all pre-trained models before use (resource Ch08.D)",
        "Enforce dependency scanning in CI/CD (resource Ch08.B)",
    ],
    "MAN-03": [
        "Deploy GDPR data governance framework (resource Ch02)",
        "Implement contamination detection in training pipelines (resource Ch03)",
        "Add data provenance signing (resource Ch01.C)",
    ],
    "MAN-04": [
        "Deploy SHAP-based explanation API (resource Ch16.E)",
        "Publish model cards for all high-risk systems",
        "Implement GDPR Art.22 right-to-explanation workflow",
    ],
}


@dataclass
class GapDetail:
    capability_id:   str
    name:            str
    current_level:   int
    target_level:    int
    gap:             int
    priority:        str
    remediation_steps: List[str]
    benchmark_level: Optional[float]    # industry peer average
    vs_benchmark:    Optional[float]    # current - benchmark (negative = below peers)


@dataclass
class GapAnalysisReport:
    organisation:    str
    sector:          str
    total_gaps:      int
    critical_count:  int
    high_count:      int
    medium_count:    int
    gaps:            List[GapDetail]
    below_benchmark: List[str]    # capability IDs where org is below peer average


class GapAnalyser:
    """
    Produces detailed gap analysis and benchmark comparison from a MaturityReport.

    Parameters
    ----------
    sector : Industry sector for benchmark comparison.
             One of: "financial_services", "healthcare", "technology", "cross_sector"
    """

    def __init__(self, sector: str = "cross_sector"):
        self._sector = sector if sector in _BENCHMARKS else "cross_sector"

    def analyse(self, report: MaturityReport) -> GapAnalysisReport:
        benchmarks = _BENCHMARKS[self._sector]
        gaps: List[GapDetail] = []
        below_benchmark: List[str] = []

        for cs in report.capability_scores:
            if cs.gap == 0:
                continue
            bm  = benchmarks.get(cs.capability_id)
            vbm = round(cs.current_level - bm, 2) if bm is not None else None
            if vbm is not None and vbm < 0:
                below_benchmark.append(cs.capability_id)

            gaps.append(GapDetail(
                capability_id     = cs.capability_id,
                name              = cs.name,
                current_level     = cs.current_level,
                target_level      = cs.target_level,
                gap               = cs.gap,
                priority          = cs.priority,
                remediation_steps = _REMEDIATION_GUIDANCE.get(cs.capability_id, []),
                benchmark_level   = bm,
                vs_benchmark      = vbm,
            ))

        gaps.sort(key=lambda g: {"critical": 0, "high": 1, "medium": 2, "low": 3}[g.priority])

        return GapAnalysisReport(
            organisation    = report.organisation,
            sector          = self._sector,
            total_gaps      = len(gaps),
            critical_count  = sum(1 for g in gaps if g.priority == "critical"),
            high_count      = sum(1 for g in gaps if g.priority == "high"),
            medium_count    = sum(1 for g in gaps if g.priority == "medium"),
            gaps            = gaps,
            below_benchmark = below_benchmark,
        )
