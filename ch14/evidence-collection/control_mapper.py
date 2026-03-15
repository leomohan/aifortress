"""
control_mapper.py  —  Compliance control-to-evidence mapper
AI Fortress · Chapter 14 · Code Sample 14.A

Maps evidence artefacts to control requirements across frameworks
(EU AI Act, NIST AI RMF, ISO 42001, ISO 27001) and identifies
coverage gaps. Produces a control mapping matrix suitable for
auditor submission.

A control is considered "satisfied" when it has at least one
active artefact AND the artefact type matches the expected
evidence category for that control.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from evidence_artefact import EvidenceArtefact, EvidenceCollector


# ── Control catalogue ─────────────────────────────────────────────────────────
# Each control has: id, framework, title, expected evidence types

_CONTROL_CATALOGUE: List[Dict] = [
    # EU AI Act
    {"id": "EU-AIA-09",   "framework": "EU AI Act",    "title": "Risk management system",                 "expected_types": ["risk_assessment", "procedure_document"]},
    {"id": "EU-AIA-10",   "framework": "EU AI Act",    "title": "Training data governance",               "expected_types": ["policy_document", "test_result", "audit_report"]},
    {"id": "EU-AIA-11",   "framework": "EU AI Act",    "title": "Technical documentation",                "expected_types": ["policy_document", "attestation", "tool_output"]},
    {"id": "EU-AIA-12",   "framework": "EU AI Act",    "title": "Logging and traceability",               "expected_types": ["log_export", "tool_output", "configuration_export"]},
    {"id": "EU-AIA-13",   "framework": "EU AI Act",    "title": "Transparency to users",                  "expected_types": ["policy_document", "procedure_document"]},
    {"id": "EU-AIA-14",   "framework": "EU AI Act",    "title": "Human oversight mechanisms",             "expected_types": ["procedure_document", "training_record", "attestation"]},
    {"id": "EU-AIA-15",   "framework": "EU AI Act",    "title": "Accuracy, robustness, cybersecurity",    "expected_types": ["test_result", "audit_report", "tool_output"]},
    # NIST AI RMF
    {"id": "NIST-GOV-1",  "framework": "NIST AI RMF", "title": "AI risk governance policies established", "expected_types": ["policy_document", "procedure_document"]},
    {"id": "NIST-MAP-1",  "framework": "NIST AI RMF", "title": "AI risks identified and mapped",          "expected_types": ["risk_assessment", "tool_output"]},
    {"id": "NIST-MEA-1",  "framework": "NIST AI RMF", "title": "AI risks measured and monitored",         "expected_types": ["test_result", "log_export", "tool_output"]},
    {"id": "NIST-MAN-1",  "framework": "NIST AI RMF", "title": "AI risks managed and treated",            "expected_types": ["risk_assessment", "procedure_document", "attestation"]},
    # ISO 42001
    {"id": "ISO42-6.1",   "framework": "ISO/IEC 42001", "title": "AI risk assessment and treatment",      "expected_types": ["risk_assessment", "audit_report"]},
    {"id": "ISO42-8.4",   "framework": "ISO/IEC 42001", "title": "AI system impact assessment",           "expected_types": ["risk_assessment", "attestation"]},
    {"id": "ISO42-9.1",   "framework": "ISO/IEC 42001", "title": "Performance monitoring and evaluation",  "expected_types": ["test_result", "log_export", "audit_report"]},
    # ISO 27001
    {"id": "ISO27-A5.23", "framework": "ISO/IEC 27001", "title": "Info security for cloud services",      "expected_types": ["configuration_export", "audit_report", "attestation"]},
    {"id": "ISO27-A8.8",  "framework": "ISO/IEC 27001", "title": "Management of technical vulnerabilities","expected_types": ["tool_output", "audit_report"]},
    # GDPR
    {"id": "GDPR-25",     "framework": "GDPR",         "title": "Data protection by design and default",  "expected_types": ["policy_document", "configuration_export", "attestation"]},
    {"id": "GDPR-35",     "framework": "GDPR",         "title": "Data protection impact assessment",      "expected_types": ["risk_assessment", "audit_report"]},
]


@dataclass
class ControlMappingEntry:
    control_id:     str
    framework:      str
    title:          str
    artefact_ids:   List[str]
    artefact_count: int
    type_match:     bool     # at least one artefact has a matching expected type
    satisfied:      bool     # has evidence AND type matches
    gap_note:       str


@dataclass
class ControlMappingMatrix:
    audit_name:        str
    total_controls:    int
    satisfied:         int
    gaps:              int
    coverage_pct:      float
    entries:           List[ControlMappingEntry]
    framework_summary: Dict[str, Dict]   # framework → {total, satisfied, coverage_pct}
    generated_at:      str

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class ControlMapper:
    """
    Maps evidence artefacts to control requirements.

    Parameters
    ----------
    frameworks : Restrict mapping to these frameworks. None = all.
    """

    def __init__(self, frameworks: Optional[List[str]] = None):
        self._frameworks = frameworks

    def map(
        self,
        collector: EvidenceCollector,
    ) -> ControlMappingMatrix:
        """Produce a full control mapping matrix from a collector's inventory."""
        inv       = collector.inventory()
        artefacts = [a for a in inv.artefacts if a.status == "active"]

        # Build lookup: control_id → list of artefacts
        ctrl_arts: Dict[str, List[EvidenceArtefact]] = {}
        for a in artefacts:
            for c in a.control_ids:
                ctrl_arts.setdefault(c, []).append(a)

        catalogue = [
            c for c in _CONTROL_CATALOGUE
            if not self._frameworks or c["framework"] in self._frameworks
        ]

        entries: List[ControlMappingEntry] = []
        for ctrl in catalogue:
            cid     = ctrl["id"]
            arts    = ctrl_arts.get(cid, [])
            types   = {a.evidence_type for a in arts}
            expected = set(ctrl["expected_types"])
            t_match = bool(types & expected)
            satisfied = bool(arts) and t_match
            gap_note  = (
                "" if satisfied else
                "No evidence collected" if not arts else
                f"Evidence type mismatch — expected one of {ctrl['expected_types']}"
            )
            entries.append(ControlMappingEntry(
                control_id     = cid,
                framework      = ctrl["framework"],
                title          = ctrl["title"],
                artefact_ids   = [a.artefact_id for a in arts],
                artefact_count = len(arts),
                type_match     = t_match,
                satisfied      = satisfied,
                gap_note       = gap_note,
            ))

        sat = sum(1 for e in entries if e.satisfied)
        cov = round(sat / len(entries) * 100, 1) if entries else 0.0

        # Per-framework summary
        fw_summary: Dict[str, Dict] = {}
        for e in entries:
            fw = e.framework
            fw_summary.setdefault(fw, {"total": 0, "satisfied": 0})
            fw_summary[fw]["total"] += 1
            if e.satisfied:
                fw_summary[fw]["satisfied"] += 1
        for fw, v in fw_summary.items():
            v["coverage_pct"] = round(v["satisfied"] / v["total"] * 100, 1)

        return ControlMappingMatrix(
            audit_name        = collector.audit_name,
            total_controls    = len(entries),
            satisfied         = sat,
            gaps              = len(entries) - sat,
            coverage_pct      = cov,
            entries           = entries,
            framework_summary = fw_summary,
            generated_at      = datetime.now(timezone.utc).isoformat(),
        )
