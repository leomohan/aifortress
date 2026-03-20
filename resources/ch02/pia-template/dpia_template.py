"""
dpia_template.py  —  GDPR Article 35 DPIA generator for ML datasets
AI Fortress · Chapter 2 · Code Sample 2.C

Generates a pre-filled DPIA document in Markdown and JSON for a given
ML training dataset, ready for DPO review.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List


@dataclass
class DPIASection:
    section_number: str
    title:          str
    content:        str
    status:         str = "DRAFT"   # DRAFT | COMPLETE | APPROVED


@dataclass
class DPIA:
    dataset_id:       str
    dataset_name:     str
    controller:       str
    dpo_name:         str
    created_at:       str = ""
    sections:         List[DPIASection] = field(default_factory=list)

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_markdown(self) -> str:
        lines = [
            f"# Data Protection Impact Assessment",
            f"**Dataset:** {self.dataset_name} (`{self.dataset_id}`)  ",
            f"**Controller:** {self.controller}  ",
            f"**DPO:** {self.dpo_name}  ",
            f"**Created:** {self.created_at}  ",
            f"**Status:** DRAFT — requires DPO review and approval",
            "",
            "---",
            "",
        ]
        for s in self.sections:
            lines += [f"## {s.section_number}. {s.title}", "", s.content, ""]
        return "\n".join(lines)

    def save_markdown(self, path: Path) -> None:
        path.write_text(self.to_markdown(), encoding="utf-8")

    def save_json(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")


def generate_ml_dpia(
    dataset_id:     str,
    dataset_name:   str,
    controller:     str,
    dpo_name:       str,
    purpose:        str,
    data_categories: List[str],
    subject_count:  int,
    third_countries: List[str] | None = None,
) -> DPIA:
    """
    Generate a pre-filled DPIA for an ML training dataset.
    Sections follow the ICO DPIA template structure.
    """
    dpia = DPIA(dataset_id=dataset_id, dataset_name=dataset_name,
                controller=controller, dpo_name=dpo_name)

    dpia.sections = [
        DPIASection("1", "Overview and Necessity",
            f"**Purpose of processing:** {purpose}\n\n"
            f"**Dataset:** {dataset_name} — {subject_count:,} data subjects.\n\n"
            f"**Data categories:** {', '.join(data_categories)}\n\n"
            "**Necessity assessment:** [TO COMPLETE] Explain why this personal data is "
            "necessary for the stated ML purpose and why less privacy-invasive alternatives "
            "are not sufficient."),
        DPIASection("2", "Consultation",
            "**DPO consulted:** Yes — [DATE]\n\n"
            "**Data subject consultation:** [TO COMPLETE] Describe whether and how data "
            "subjects were consulted, or justify why consultation was not carried out."),
        DPIASection("3", "Data Flows",
            f"**Source:** [TO COMPLETE]\n\n"
            f"**Storage location:** [TO COMPLETE]\n\n"
            f"**Third-country transfers:** {', '.join(third_countries) if third_countries else 'None identified'}\n\n"
            "**Transfer mechanism:** [TO COMPLETE if transfers identified — SCCs/BCRs/adequacy decision]"),
        DPIASection("4", "Privacy Risks",
            "| Risk | Likelihood | Severity | Risk Level |\n"
            "|------|-----------|----------|------------|\n"
            "| Unauthorised access to training data | Medium | High | HIGH |\n"
            "| Re-identification of anonymised subjects | Low | High | MEDIUM |\n"
            "| Model inversion revealing training data | Low | High | MEDIUM |\n"
            "| Membership inference attack | Medium | Medium | MEDIUM |\n"
            "| Data subject erasure not propagated to model | Medium | High | HIGH |\n\n"
            "[TO COMPLETE] Add organisation-specific risks."),
        DPIASection("5", "Risk Mitigation Measures",
            "| Risk | Mitigation | Residual Risk | Owner |\n"
            "|------|-----------|--------------|-------|\n"
            "| Unauthorised access | AES-256-GCM encryption at rest; RBAC; audit logging | LOW | Security Team |\n"
            "| Re-identification | k-anonymity (k≥5); pseudonymisation | LOW | Data Team |\n"
            "| Model inversion | Differential privacy (ε≤1.0); output filtering | MEDIUM | ML Team |\n"
            "| Membership inference | DP-SGD training; prediction confidence suppression | MEDIUM | ML Team |\n"
            "| Erasure propagation | Model retraining pipeline triggered on erasure | LOW | ML Team |\n\n"
            "[TO COMPLETE] Confirm mitigations implemented and residual risk accepted by DPO."),
        DPIASection("6", "DPO Sign-off",
            "**DPO Name:** " + dpo_name + "\n\n"
            "**Sign-off date:** [TO COMPLETE]\n\n"
            "**Decision:** ☐ Approved  ☐ Approved with conditions  ☐ Rejected\n\n"
            "**Conditions / Notes:** [TO COMPLETE]\n\n"
            "**Next review date:** [TO COMPLETE — recommend annual review or on material change]"),
    ]
    return dpia
