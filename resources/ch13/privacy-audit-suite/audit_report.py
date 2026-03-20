"""
audit_report.py  —  Privacy audit report assembly
AI Fortress · Chapter 13 · Code Sample 13.D

Assembles membership inference, attribute inference, and canary audit
findings into a unified privacy audit report with severity ratings
and remediation recommendations.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from membership_inference import MIAResult
from attribute_inference import AttributeInferenceRisk
from canary_auditor import CanaryAuditReport


_SEVERITY_ORDER = {"low": 0, "moderate": 1, "high": 2, "critical": 3}


@dataclass
class PrivacyAuditReport:
    report_id:      str
    model_name:     str
    model_version:  str
    audited_at:     str
    audited_by:     str

    mia_result:              Optional[MIAResult]
    attribute_risks:         List[AttributeInferenceRisk]
    canary_report:           Optional[CanaryAuditReport]

    overall_severity:        str
    findings_summary:        List[str]
    recommendations:         List[str]

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        return (
            f"Privacy Audit [{self.overall_severity.upper()}] — "
            f"{self.model_name}@{self.model_version}: "
            f"{len(self.findings_summary)} finding(s). "
            f"Audited by {self.audited_by} at {self.audited_at}."
        )


class PrivacyAuditReporter:
    """Assembles privacy audit findings into a structured report."""

    def generate(
        self,
        model_name:     str,
        model_version:  str,
        audited_by:     str,
        mia_result:     Optional[MIAResult]           = None,
        attribute_risks: Optional[List[AttributeInferenceRisk]] = None,
        canary_report:  Optional[CanaryAuditReport]  = None,
    ) -> PrivacyAuditReport:
        findings:    List[str] = []
        recs:        List[str] = []
        max_sev      = "low"

        if mia_result:
            findings.append(
                f"MIA: AUC={mia_result.attack_auc:.3f}, "
                f"advantage={mia_result.advantage:.3f} ({mia_result.severity})"
            )
            if _SEVERITY_ORDER[mia_result.severity] > _SEVERITY_ORDER[max_sev]:
                max_sev = mia_result.severity
            if mia_result.severity in ("high", "critical"):
                recs.append(
                    "Apply differential privacy training (ε ≤ 10) to reduce "
                    "membership inference advantage."
                )

        for risk in (attribute_risks or []):
            findings.append(
                f"Attribute inference '{risk.attribute_name}': "
                f"risk={risk.risk_score:.3f} ({risk.severity})"
            )
            if _SEVERITY_ORDER[risk.severity] > _SEVERITY_ORDER[max_sev]:
                max_sev = risk.severity
            if risk.severity in ("high", "critical"):
                recs.append(
                    f"Consider output perturbation or suppressing confidence "
                    f"for attribute '{risk.attribute_name}'."
                )

        if canary_report:
            findings.append(
                f"Canary: max_exposure={canary_report.max_exposure_score:.2f} bits "
                f"({canary_report.severity})"
            )
            if _SEVERITY_ORDER[canary_report.severity] > _SEVERITY_ORDER[max_sev]:
                max_sev = canary_report.severity
            if canary_report.severity in ("high", "critical"):
                recs.append(canary_report.recommendation)

        if not recs:
            recs.append("No critical findings. Maintain privacy monitoring cadence.")

        return PrivacyAuditReport(
            report_id       = str(uuid.uuid4()),
            model_name      = model_name,
            model_version   = model_version,
            audited_at      = datetime.now(timezone.utc).isoformat(),
            audited_by      = audited_by,
            mia_result      = mia_result,
            attribute_risks = attribute_risks or [],
            canary_report   = canary_report,
            overall_severity = max_sev,
            findings_summary = findings,
            recommendations  = recs,
        )
