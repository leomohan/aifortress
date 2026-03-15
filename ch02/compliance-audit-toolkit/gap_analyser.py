"""
gap_analyser.py  —  Compare evidence to required controls and classify gaps
AI Fortress · Chapter 2 · Code Sample 2.C
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List
from control_registry import Control, ControlRegistry, ControlStatus
from evidence_collector import AuditEvidence


@dataclass
class ControlAssessment:
    control:    Control
    status:     ControlStatus
    evidence_met:    List[str]
    evidence_missing: List[str]
    notes:      str = ""


@dataclass
class GapReport:
    dataset_id:   str
    regulations:  List[str]
    assessments:  List[ControlAssessment]
    generated_at: str = ""

    def __post_init__(self):
        from datetime import datetime, timezone
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def by_status(self, status: ControlStatus) -> List[ControlAssessment]:
        return [a for a in self.assessments if a.status == status]

    def summary_counts(self) -> Dict[str, int]:
        return {s.value: len(self.by_status(s)) for s in ControlStatus}


class GapAnalyser:
    def __init__(self, registry: ControlRegistry | None = None):
        self.registry = registry or ControlRegistry()

    def analyse(
        self,
        evidence:    AuditEvidence,
        regulations: List[str] | None = None,
    ) -> GapReport:
        regs = [r.upper().replace("-","_") for r in (regulations or ["GDPR","CCPA","HIPAA","EU_AI_ACT"])]
        controls = [c for c in self.registry.all_controls() if c.regulation in regs]
        assessments: List[ControlAssessment] = []

        for control in controls:
            met     = [k for k in control.evidence_keys if evidence.has(k)]
            missing = [k for k in control.evidence_keys if not evidence.has(k)]

            if not missing:
                status = ControlStatus.COMPLIANT
            elif met:
                status = ControlStatus.PARTIAL
            else:
                status = ControlStatus.GAP

            assessments.append(ControlAssessment(
                control          = control,
                status           = status,
                evidence_met     = met,
                evidence_missing = missing,
            ))

        return GapReport(
            dataset_id  = evidence.dataset_id,
            regulations = regs,
            assessments = assessments,
        )
