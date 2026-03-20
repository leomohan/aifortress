"""
robustness_reporter.py  —  Physical adversarial robustness report
AI Fortress · Chapter 15 · Code Sample 15.E

Assembles patch robustness and environmental distortion results into
a unified robustness evaluation report with pass/fail gates.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from patch_robustness_tester import PatchRobustnessResult
from env_distortion_simulator import DistortionEvalResult


@dataclass
class RobustnessReport:
    report_id:        str
    model_name:       str
    model_version:    str
    evaluated_at:     str
    patch_result:     Optional[PatchRobustnessResult]
    distortion_results: List[DistortionEvalResult]
    overall_grade:    str        # "PASS" | "CONDITIONAL" | "FAIL"
    worst_drop:       float      # highest accuracy drop across all tests
    findings:         List[str]
    recommendations:  List[str]

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        return (
            f"Robustness [{self.overall_grade}] — {self.model_name}@{self.model_version}: "
            f"worst_drop={self.worst_drop:.3f}. {len(self.findings)} finding(s)."
        )


class RobustnessReporter:
    """Assembles robustness evaluation results into a structured report."""

    _FAIL_THRESHOLD        = 0.30
    _CONDITIONAL_THRESHOLD = 0.10

    def generate(
        self,
        model_name:         str,
        model_version:      str,
        patch_result:       Optional[PatchRobustnessResult] = None,
        distortion_results: Optional[List[DistortionEvalResult]] = None,
    ) -> RobustnessReport:
        findings:   List[str] = []
        recs:       List[str] = []
        drops:      List[float] = []

        if patch_result:
            drops.append(patch_result.accuracy_drop)
            if patch_result.severity in ("critical", "high"):
                findings.append(
                    f"Patch attack: {patch_result.accuracy_drop*100:.1f}% accuracy drop "
                    f"({patch_result.severity})"
                )
                recs.append(patch_result.recommendation)

        for dr in (distortion_results or []):
            drops.append(dr.accuracy_drop)
            if dr.accuracy_drop > self._conditional_threshold:
                findings.append(
                    f"{dr.distortion_type} (s={dr.severity:.2f}): "
                    f"{dr.accuracy_drop*100:.1f}% drop"
                )

        worst = max(drops) if drops else 0.0
        if worst >= self._FAIL_THRESHOLD:
            grade = "FAIL"
            recs.insert(0, "Model fails robustness gate. Do not deploy to production.")
        elif worst >= self._conditional_threshold:
            grade = "CONDITIONAL"
            recs.insert(0, "Conditional pass. Address high-severity findings before deployment.")
        else:
            grade = "PASS"

        if not recs:
            recs.append("Model meets all robustness thresholds.")

        return RobustnessReport(
            report_id          = str(uuid.uuid4()),
            model_name         = model_name,
            model_version      = model_version,
            evaluated_at       = datetime.now(timezone.utc).isoformat(),
            patch_result       = patch_result,
            distortion_results = distortion_results or [],
            overall_grade      = grade,
            worst_drop         = round(worst, 4),
            findings           = findings,
            recommendations    = recs,
        )

    @property
    def _conditional_threshold(self) -> float:
        return self._CONDITIONAL_THRESHOLD
