"""
pipeline_monitor.py  —  Stage-to-stage quality regression detection
AI Fortress · Chapter 3 · Code Sample 3.C

Tracks data quality scores across pipeline stages (raw → cleaned → featured
→ train/val/test split) and flags regressions where quality drops between
consecutive stages — which can indicate a misconfigured preprocessing step
or adversarial data injection at a later stage.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from quality_scorer import QualityScore


@dataclass
class PipelineStage:
    stage_name:   str
    score:        QualityScore
    recorded_at:  str = ""

    def __post_init__(self):
        if not self.recorded_at:
            self.recorded_at = datetime.now(timezone.utc).isoformat()


@dataclass
class QualityRegression:
    from_stage:   str
    to_stage:     str
    dimension:    str        # which dimension dropped
    drop_amount:  float
    severity:     str        # "warning" | "critical"
    description:  str


class PipelineMonitor:
    """
    Tracks quality scores across pipeline stages and detects regressions.

    Parameters
    ----------
    regression_threshold : Score drop (in points) that triggers a warning
    critical_threshold   : Score drop that triggers a critical alert
    """

    def __init__(
        self,
        regression_threshold: float = 5.0,
        critical_threshold:   float = 15.0,
    ):
        self.regression_threshold = regression_threshold
        self.critical_threshold   = critical_threshold
        self.stages: List[PipelineStage] = []

    def record(self, stage_name: str, score: QualityScore) -> None:
        self.stages.append(PipelineStage(stage_name=stage_name, score=score))

    def detect_regressions(self) -> List[QualityRegression]:
        regressions: List[QualityRegression] = []
        for i in range(1, len(self.stages)):
            prev = self.stages[i - 1]
            curr = self.stages[i]

            # Check composite score
            drop = prev.score.score - curr.score.score
            if drop >= self.regression_threshold:
                severity = "critical" if drop >= self.critical_threshold else "warning"
                regressions.append(QualityRegression(
                    from_stage  = prev.stage_name,
                    to_stage    = curr.stage_name,
                    dimension   = "composite",
                    drop_amount = round(drop, 2),
                    severity    = severity,
                    description = (
                        f"Composite quality score dropped {drop:.1f} points: "
                        f"{prev.score.score} → {curr.score.score} "
                        f"({prev.stage_name} → {curr.stage_name})"
                    ),
                ))

            # Check per-dimension
            for dim in ["completeness", "schema", "consistency", "statistical"]:
                prev_dim = prev.score.dimension_scores.get(dim, 100.0)
                curr_dim = curr.score.dimension_scores.get(dim, 100.0)
                dim_drop = prev_dim - curr_dim
                if dim_drop >= self.regression_threshold:
                    severity = "critical" if dim_drop >= self.critical_threshold else "warning"
                    regressions.append(QualityRegression(
                        from_stage  = prev.stage_name,
                        to_stage    = curr.stage_name,
                        dimension   = dim,
                        drop_amount = round(dim_drop, 2),
                        severity    = severity,
                        description = (
                            f"{dim.capitalize()} score dropped {dim_drop:.1f} points: "
                            f"{prev_dim:.1f} → {curr_dim:.1f} "
                            f"({prev.stage_name} → {curr.stage_name})"
                        ),
                    ))

        return regressions

    def report(self) -> dict:
        regressions = self.detect_regressions()
        return {
            "stages": [
                {
                    "stage":      s.stage_name,
                    "score":      s.score.score,
                    "passed":     s.score.passed,
                    "dimensions": s.score.dimension_scores,
                    "recorded_at": s.recorded_at,
                }
                for s in self.stages
            ],
            "regressions": [asdict(r) for r in regressions],
            "n_critical":  sum(1 for r in regressions if r.severity == "critical"),
            "n_warnings":  sum(1 for r in regressions if r.severity == "warning"),
        }

    def save_report(self, path: Path | str) -> None:
        Path(path).write_text(json.dumps(self.report(), indent=2), encoding="utf-8")
