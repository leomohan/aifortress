"""
maturity_scorer.py  —  AI security maturity assessment scorer
AI Fortress · Chapter 14 · Code Sample 14.B

Scores an organisation against the AI security maturity model, produces
domain-level and overall scores, identifies gaps, and generates a
prioritised capability improvement roadmap.

Usage:
    scorer   = MaturityScorer()
    response = scorer.assess({"GOV-01": 3, "MAP-01": 2, ...})
    report   = scorer.report(response)
    print(report.summary())
"""
from __future__ import annotations

import json
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from maturity_model import CAPABILITIES, DOMAINS, MATURITY_LABELS, MaturityCapability


@dataclass
class CapabilityScore:
    capability_id:   str
    name:            str
    domain:          str
    current_level:   int
    target_level:    int
    gap:             int
    weight:          float
    weighted_score:  float
    criteria_current: str
    criteria_target:  str
    priority:         str    # "critical" | "high" | "medium" | "low"


@dataclass
class DomainScore:
    domain:         str
    weighted_avg:   float
    target_avg:     float
    gap:            float
    n_capabilities: int
    grade:          str    # A–F


@dataclass
class MaturityReport:
    assessment_id:    str
    assessed_at:      str
    organisation:     str
    overall_score:    float      # weighted average across all capabilities
    overall_target:   float
    overall_gap:      float
    overall_grade:    str
    domain_scores:    List[DomainScore]
    capability_scores: List[CapabilityScore]
    critical_gaps:    List[str]  # capability IDs with gap ≥ 3
    roadmap:          List[dict] # prioritised improvement items

    def summary(self) -> str:
        return (
            f"Maturity Assessment [{self.overall_grade}] — "
            f"{self.organisation}: overall score {self.overall_score:.1f}/5.0, "
            f"target {self.overall_target:.1f}/5.0, gap {self.overall_gap:.1f}. "
            f"{len(self.critical_gaps)} critical gap(s)."
        )

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class MaturityScorer:
    """
    Scores an organisation against the AI security maturity model.

    Parameters
    ----------
    target_levels  : Optional dict of capability_id → target level override.
                     Default target is 3 (Defined) for all capabilities.
    organisation   : Organisation name for report labelling.
    """

    _DEFAULT_TARGET = 3

    def __init__(
        self,
        target_levels: Optional[Dict[str, int]] = None,
        organisation:  str = "Organisation",
    ):
        self._targets = target_levels or {}
        self._org     = organisation

    def assess(
        self,
        scores: Dict[str, int],   # capability_id → current level (0–5)
    ) -> MaturityReport:
        """
        Produce a maturity assessment report.

        Parameters
        ----------
        scores : Dict mapping capability_id to current maturity level (0–5).
                 Missing capabilities are scored as 0 (Non-existent).
        """
        cap_scores: List[CapabilityScore] = []

        for cap in CAPABILITIES:
            current = max(0, min(5, scores.get(cap.capability_id, 0)))
            target  = max(0, min(5, self._targets.get(cap.capability_id, self._DEFAULT_TARGET)))
            gap     = max(0, target - current)
            ws      = current * cap.weight
            priority = (
                "critical" if gap >= 3 else
                "high"     if gap == 2 else
                "medium"   if gap == 1 else
                "low"
            )
            cap_scores.append(CapabilityScore(
                capability_id    = cap.capability_id,
                name             = cap.name,
                domain           = cap.domain,
                current_level    = current,
                target_level     = target,
                gap              = gap,
                weight           = cap.weight,
                weighted_score   = round(ws, 3),
                criteria_current = cap.level_criteria.get(current, "N/A"),
                criteria_target  = cap.level_criteria.get(target, "N/A"),
                priority         = priority,
            ))

        # Domain scores
        domain_scores: List[DomainScore] = []
        for domain in DOMAINS:
            domain_caps = [c for c in cap_scores if c.domain == domain]
            if not domain_caps:
                continue
            total_weight  = sum(c.weight for c in domain_caps)
            w_avg_current = sum(c.current_level * c.weight for c in domain_caps) / total_weight
            w_avg_target  = sum(c.target_level  * c.weight for c in domain_caps) / total_weight
            domain_scores.append(DomainScore(
                domain         = domain,
                weighted_avg   = round(w_avg_current, 2),
                target_avg     = round(w_avg_target, 2),
                gap            = round(max(0, w_avg_target - w_avg_current), 2),
                n_capabilities = len(domain_caps),
                grade          = self._grade(w_avg_current),
            ))

        # Overall score
        total_weight   = sum(c.weight for c in CAPABILITIES)
        overall_score  = sum(c.weighted_score for c in cap_scores) / total_weight
        overall_target = sum(c.target_level * c.weight for c in cap_scores) / total_weight
        overall_gap    = max(0, overall_target - overall_score)

        critical_gaps = [c.capability_id for c in cap_scores if c.gap >= 3]

        # Roadmap: sort by (priority, domain) and group into waves
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_caps = sorted(
            [c for c in cap_scores if c.gap > 0],
            key=lambda c: (priority_order[c.priority], c.domain)
        )
        roadmap = []
        for wave, (label, prios) in enumerate(
            [("Wave 1 (0-3 months)",  ["critical"]),
             ("Wave 2 (3-6 months)",  ["high"]),
             ("Wave 3 (6-12 months)", ["medium", "low"])], start=1
        ):
            items = [c for c in sorted_caps if c.priority in prios]
            if items:
                roadmap.append({
                    "wave":    label,
                    "items":   [{"id": c.capability_id, "name": c.name,
                                 "from": c.current_level, "to": c.target_level,
                                 "domain": c.domain} for c in items],
                })

        return MaturityReport(
            assessment_id    = str(uuid.uuid4())[:8],
            assessed_at      = datetime.now(timezone.utc).isoformat(),
            organisation     = self._org,
            overall_score    = round(overall_score, 2),
            overall_target   = round(overall_target, 2),
            overall_gap      = round(overall_gap, 2),
            overall_grade    = self._grade(overall_score),
            domain_scores    = domain_scores,
            capability_scores = cap_scores,
            critical_gaps    = critical_gaps,
            roadmap          = roadmap,
        )

    @staticmethod
    def _grade(score: float) -> str:
        return ("A" if score >= 4.5 else "B" if score >= 3.5 else
                "C" if score >= 2.5 else "D" if score >= 1.5 else "F")
