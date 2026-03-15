"""
evaluation_formatter.py  —  Evaluation results formatter for model cards
AI Fortress · Chapter 12 · Code Sample 12.B

Formats evaluation results from multiple benchmark datasets into a
consistent structure. Tracks per-slice performance and highlights
performance gaps above a configurable threshold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MetricResult:
    name:    str          # e.g. "accuracy", "f1", "BLEU"
    value:   float
    dataset: str
    split:   str = "test"
    slice_name:  str = ""   # e.g. "female", "age_18-25", "geography:EU"
    slice_value: str = ""


@dataclass
class PerformanceGap:
    metric:      str
    dataset:     str
    dimension:   str          # slice dimension e.g. "gender"
    best_slice:  str
    best_value:  float
    worst_slice: str
    worst_value: float
    gap:         float
    severity:    str          # "critical" | "notable" | "minor"


@dataclass
class EvaluationReport:
    results:          List[MetricResult]
    performance_gaps: List[PerformanceGap]

    def summary_table(self) -> str:
        """Return a Markdown table of overall (non-slice) results."""
        overall = [r for r in self.results if not r.slice_name]
        if not overall:
            return "_No overall evaluation results._\n"
        rows = ["| Dataset | Split | Metric | Value |",
                "|---------|-------|--------|-------|"]
        for r in overall:
            rows.append(f"| {r.dataset} | {r.split} | {r.name} | {r.value:.4f} |")
        return "\n".join(rows) + "\n"

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


class EvaluationFormatter:
    """
    Formats evaluation results for model card inclusion.

    Parameters
    ----------
    gap_threshold_critical : Performance gap above which severity = "critical".
    gap_threshold_notable  : Performance gap above which severity = "notable".
    """

    def __init__(
        self,
        gap_threshold_critical: float = 0.10,
        gap_threshold_notable:  float = 0.05,
    ):
        self._crit   = gap_threshold_critical
        self._notable = gap_threshold_notable

    def format(self, results: List[MetricResult]) -> EvaluationReport:
        gaps = self._detect_gaps(results)
        return EvaluationReport(results=results, performance_gaps=gaps)

    def _detect_gaps(self, results: List[MetricResult]) -> List[PerformanceGap]:
        """Find performance gaps across slices for the same metric + dataset."""
        from collections import defaultdict

        # Group by (metric, dataset): slice_name → value
        groups: Dict[tuple, Dict[str, float]] = defaultdict(dict)
        for r in results:
            if r.slice_name:
                groups[(r.name, r.dataset, r.slice_name.split(":")[0])][r.slice_name] = r.value

        gaps = []
        seen: set = set()
        for (metric, dataset, dimension), slices in groups.items():
            key = (metric, dataset, dimension)
            if key in seen or len(slices) < 2:
                continue
            seen.add(key)
            best_s  = max(slices, key=slices.get)
            worst_s = min(slices, key=slices.get)
            gap     = slices[best_s] - slices[worst_s]
            if gap < 0.001:
                continue
            severity = ("critical" if gap >= self._crit
                        else "notable" if gap >= self._notable
                        else "minor")
            gaps.append(PerformanceGap(
                metric      = metric,
                dataset     = dataset,
                dimension   = dimension,
                best_slice  = best_s,
                best_value  = round(slices[best_s],  4),
                worst_slice = worst_s,
                worst_value = round(slices[worst_s], 4),
                gap         = round(gap, 4),
                severity    = severity,
            ))
        return gaps
