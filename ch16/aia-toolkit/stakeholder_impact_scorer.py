"""
stakeholder_impact_scorer.py  —  Stakeholder impact scoring for AIA
AI Fortress · Chapter 16 · Code Sample 16.C

Scores the impact of an AI system on each identified stakeholder group
across multiple impact dimensions (autonomy, dignity, fairness,
economic, safety, privacy). Produces a per-stakeholder impact matrix
and an overall impact level for AIA reporting.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


_DIMENSIONS = ["autonomy", "dignity", "fairness", "economic", "safety", "privacy"]
_LEVEL_MAP  = {0: "none", 1: "minimal", 2: "low", 3: "moderate", 4: "high", 5: "critical"}


@dataclass
class StakeholderScore:
    stakeholder:      str
    scores:           Dict[str, int]    # dimension → score (0–5)
    total_score:      int
    impact_level:     str               # "none"|"minimal"|"low"|"moderate"|"high"|"critical"
    highest_dimension: str
    notes:            str = ""


@dataclass
class StakeholderImpactMatrix:
    system_name:   str
    stakeholders:  List[StakeholderScore]
    overall_level: str
    critical_dims: List[str]   # dimensions scoring ≥ 4 for any stakeholder


class StakeholderImpactScorer:
    """Scores AI system impacts across stakeholders and impact dimensions."""

    def score(
        self,
        system_name:  str,
        stakeholders: List[Dict],
    ) -> StakeholderImpactMatrix:
        """
        Parameters
        ----------
        stakeholders : List of dicts with keys:
            name        : Stakeholder name (str)
            scores      : Dict[dimension → int 0-5]  (missing = 0)
            notes       : Optional explanation (str)
        """
        scored: List[StakeholderScore] = []
        all_dims_scores: Dict[str, List[int]] = {d: [] for d in _DIMENSIONS}

        for sh in stakeholders:
            name   = sh["name"]
            raw    = sh.get("scores", {})
            scores = {d: max(0, min(5, raw.get(d, 0))) for d in _DIMENSIONS}
            total  = sum(scores.values())
            level  = _LEVEL_MAP.get(min(5, total // len(_DIMENSIONS)), "none")
            highest = max(scores, key=scores.get)
            scored.append(StakeholderScore(
                stakeholder=name, scores=scores, total_score=total,
                impact_level=level, highest_dimension=highest,
                notes=sh.get("notes", ""),
            ))
            for d, v in scores.items():
                all_dims_scores[d].append(v)

        # Overall level = max individual impact
        max_total = max((s.total_score for s in scored), default=0)
        overall   = _LEVEL_MAP.get(min(5, max_total // len(_DIMENSIONS)), "none")
        critical  = [d for d, vals in all_dims_scores.items() if max(vals, default=0) >= 4]

        return StakeholderImpactMatrix(
            system_name=system_name, stakeholders=scored,
            overall_level=overall, critical_dims=critical,
        )
