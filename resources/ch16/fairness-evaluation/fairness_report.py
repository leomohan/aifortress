"""
fairness_report.py  —  Structured fairness evaluation report
AI Fortress · Chapter 16 · Code Sample 16.A

Assembles group and intersectional fairness findings into a single
structured report with regulatory context and remediation guidance.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from fairness_metrics import FairnessMetrics
from intersectional_fairness import IntersectionalFairnessReport


@dataclass
class FairnessEvaluationReport:
    report_id:         str
    model_name:        str
    model_version:     str
    protected_attribute: str
    evaluated_at:      str
    group_fairness:    FairnessMetrics
    intersectional:    Optional[IntersectionalFairnessReport]
    overall_grade:     str
    regulatory_flags:  List[str]
    recommendations:   List[str]

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        return (
            f"Fairness Report [{self.overall_grade}] — "
            f"{self.model_name}@{self.model_version} "
            f"on '{self.protected_attribute}': "
            f"{len(self.group_fairness.violations)} violation(s). "
            f"{len(self.recommendations)} recommendation(s)."
        )


class FairnessReportBuilder:
    """Assembles a full fairness evaluation report."""

    _EU_AI_ACT_HIGH_RISK = {
        "credit", "employment", "education", "healthcare",
        "law enforcement", "migration", "critical infrastructure",
    }

    def build(
        self,
        model_name:          str,
        model_version:       str,
        protected_attribute: str,
        group_fairness:      FairnessMetrics,
        intersectional:      Optional[IntersectionalFairnessReport] = None,
        use_case:            str = "",
    ) -> FairnessEvaluationReport:
        reg_flags: List[str] = []
        recs:      List[str] = []

        if any(uc in use_case.lower() for uc in self._EU_AI_ACT_HIGH_RISK):
            reg_flags.append(
                f"EU AI Act high-risk use case ('{use_case}'): "
                "Art.10 bias-free training and Art.13 transparency required."
            )

        if group_fairness.violations:
            recs.extend([
                "Apply post-processing threshold optimisation (resource 16.B) to equalise rates.",
                "Review training data for representation gaps (resource 16.B reweighing).",
            ])

        if intersectional and intersectional.violations:
            recs.append(
                f"Intersectional parity violation detected: subgroup '{intersectional.worst_subgroup}' "
                f"has lowest positive rate. Investigate data collection for this subgroup."
            )

        grades = [group_fairness.overall_fairness_grade]
        if intersectional:
            grades.append(intersectional.grade)
        overall = min(grades, key=lambda g: "ABCDF".index(g))

        if not recs:
            recs.append("No fairness violations detected at current thresholds.")

        return FairnessEvaluationReport(
            report_id          = str(uuid.uuid4()),
            model_name         = model_name,
            model_version      = model_version,
            protected_attribute = protected_attribute,
            evaluated_at       = datetime.now(timezone.utc).isoformat(),
            group_fairness     = group_fairness,
            intersectional     = intersectional,
            overall_grade      = overall,
            regulatory_flags   = reg_flags,
            recommendations    = recs,
        )
