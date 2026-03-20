"""
ensemble_scorer.py  —  Combined injection score and evidence aggregator
AI Fortress · Chapter 5 · Code Sample 5.C

Combines pattern detector and heuristic analyser scores into a single
calibrated injection probability using a weighted ensemble.

Weights are configurable; defaults reflect empirical performance:
  Pattern score contributes more (0.70) because high-confidence signatures
  are very precise. Heuristic score fills the gap (0.30) for novel attacks
  that pattern signatures have not yet catalogued.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from pattern_detector import PatternDetector, PatternMatch
from heuristic_analyser import HeuristicAnalyser, HeuristicReport


@dataclass
class EnsembleResult:
    score:          float          # Combined injection probability [0, 1]
    pattern_score:  float
    heuristic_score: float
    pattern_matches: List[PatternMatch]
    heuristic_signals: List[str]
    evidence:       List[str]      # Human-readable evidence list
    top_severity:   str            # "critical" | "high" | "medium" | "low" | "none"


class EnsembleScorer:
    """
    Weighted ensemble of pattern and heuristic injection detectors.

    Parameters
    ----------
    pattern_weight   : Weight for pattern detector score (default 0.70).
    heuristic_weight : Weight for heuristic analyser score (default 0.30).
    """

    def __init__(
        self,
        pattern_weight:   float = 0.70,
        heuristic_weight: float = 0.30,
    ):
        assert abs(pattern_weight + heuristic_weight - 1.0) < 1e-6, \
            "Weights must sum to 1.0"
        self.pattern_weight   = pattern_weight
        self.heuristic_weight = heuristic_weight
        self._pattern_det     = PatternDetector()
        self._heuristic_an    = HeuristicAnalyser()

    def score(
        self,
        user_prompt:    str,
        system_context: str = "",
    ) -> EnsembleResult:
        """
        Score a user prompt for injection probability.
        Returns an EnsembleResult with the combined score and evidence.
        """
        # Run both detectors
        pattern_matches  = self._pattern_det.detect(user_prompt)
        pattern_score    = self._pattern_det.score(user_prompt)
        heuristic_report = self._heuristic_an.analyse(user_prompt, system_context)
        heuristic_score  = heuristic_report.total_score

        # Weighted combination
        combined = (
            self.pattern_weight   * pattern_score +
            self.heuristic_weight * heuristic_score
        )
        # Boost: if any critical pattern found, floor the combined score at 0.80
        if any(m.severity == "critical" for m in pattern_matches):
            combined = max(combined, 0.80)

        combined = round(min(combined, 1.0), 4)

        # Top severity
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        severities = [m.severity for m in pattern_matches]
        top_sev    = max(severities, key=lambda s: sev_order.get(s, 0)) if severities else "none"

        # Evidence list
        evidence: List[str] = []
        for m in pattern_matches:
            evidence.append(
                f"[{m.severity.upper()}] Pattern {m.pattern_id} ({m.category}): "
                f"'{m.matched_text[:80]}'"
            )
        for f in heuristic_report.findings:
            if f.score > 0.0:
                evidence.append(f"[HEURISTIC] {f.signal}: {f.detail}")

        return EnsembleResult(
            score             = combined,
            pattern_score     = round(pattern_score, 4),
            heuristic_score   = round(heuristic_score, 4),
            pattern_matches   = pattern_matches,
            heuristic_signals = heuristic_report.signals,
            evidence          = evidence,
            top_severity      = top_sev,
        )
