"""
evidence_package_builder.py  —  Compliance evidence package builder
AI Fortress · Chapter 14 · Code Sample 14.A

Assembles a complete, audit-ready compliance evidence package from
individual artefacts and control mappings.  The package contains:
  - A manifest (index of all artefacts with hashes and metadata)
  - A coverage report (which controls are satisfied vs. outstanding)
  - A regulatory mapping summary (frameworks → controls → evidence)
  - An evidence index JSON suitable for submission to an auditor

The package does NOT bundle the artefact bytes themselves (they may be
large binaries); instead it records hashes and source references so
auditors can verify integrity when retrieving artefacts from their
canonical locations.

Typical workflow:
  1. Use EvidenceCollector (evidence_artefact.py) to collect artefacts.
  2. Use ControlMapper (control_mapper.py) to map artefacts → controls.
  3. Call EvidencePackageBuilder.build() to produce the final package.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from evidence_artefact import EvidenceArtefact, EvidenceCollector
from control_mapper import ControlMapper, ControlMappingEntry


@dataclass
class ControlCoverage:
    control_id:       str
    framework:        str
    satisfied:        bool
    artefact_ids:     List[str]
    outstanding_gaps: List[str]


@dataclass
class EvidencePackage:
    package_id:        str
    audit_name:        str
    prepared_by:       str
    prepared_at:       str
    audit_period:      str
    total_artefacts:   int
    total_controls:    int
    satisfied_controls: int
    outstanding_controls: int
    coverage_pct:      float
    artefacts:         List[dict]       # serialised EvidenceArtefact list
    control_coverage:  List[ControlCoverage]
    framework_summary: Dict[str, dict]  # framework → {total, satisfied, pct}
    package_hash:      str              # SHA-256 of package manifest JSON

    def coverage_grade(self) -> str:
        p = self.coverage_pct
        return "A" if p >= 0.95 else "B" if p >= 0.85 else \
               "C" if p >= 0.70 else "D" if p >= 0.50 else "F"

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        return (
            f"Evidence package '{self.audit_name}' [{self.coverage_grade()}]: "
            f"{self.satisfied_controls}/{self.total_controls} controls satisfied "
            f"({self.coverage_pct:.0%}), {self.total_artefacts} artefacts."
        )


class EvidencePackageBuilder:
    """
    Assembles an audit-ready compliance evidence package.

    Parameters
    ----------
    required_controls : Dict mapping control_id → framework name.
                        These are the controls that MUST be satisfied
                        for a clean audit opinion.
    prepared_by       : Name of the person or team preparing the package.
    """

    def __init__(
        self,
        required_controls: Dict[str, str],   # control_id → framework
        prepared_by:       str = "ai-security-team",
    ):
        self._required  = required_controls
        self._preparer  = prepared_by

    def build(
        self,
        collector:    EvidenceCollector,
        audit_period: str,
    ) -> EvidencePackage:
        """
        Build the evidence package from a populated EvidenceCollector.

        Parameters
        ----------
        collector    : Populated EvidenceCollector with collected artefacts.
        audit_period : Audit period label (e.g. "2026-Q1").
        """
        inv        = collector.inventory()
        artefacts  = inv.artefacts

        # Build control → artefact mapping
        ctrl_to_arts: Dict[str, List[str]] = {}
        for art in artefacts:
            for ctrl in art.control_ids:
                ctrl_to_arts.setdefault(ctrl, []).append(art.artefact_id)

        coverage: List[ControlCoverage] = []
        framework_data: Dict[str, dict] = {}

        for ctrl_id, framework in self._required.items():
            art_ids  = ctrl_to_arts.get(ctrl_id, [])
            satisfied = len(art_ids) > 0
            gaps      = [] if satisfied else [f"No evidence collected for {ctrl_id}"]

            coverage.append(ControlCoverage(
                control_id       = ctrl_id,
                framework        = framework,
                satisfied        = satisfied,
                artefact_ids     = art_ids,
                outstanding_gaps = gaps,
            ))

            fw = framework_data.setdefault(framework, {"total": 0, "satisfied": 0})
            fw["total"]     += 1
            fw["satisfied"] += int(satisfied)

        for fw, d in framework_data.items():
            d["coverage_pct"] = round(d["satisfied"] / d["total"], 4) if d["total"] else 0.0

        total     = len(self._required)
        satisfied_n = sum(1 for c in coverage if c.satisfied)
        cov_pct   = round(satisfied_n / total, 4) if total else 0.0

        # Serialise artefacts for the package manifest
        import dataclasses
        arts_dict = [dataclasses.asdict(a) for a in artefacts]

        # Hash the manifest for tamper-evidence
        manifest_str  = json.dumps(
            {"artefacts": arts_dict, "coverage": [dataclasses.asdict(c) for c in coverage]},
            sort_keys=True
        )
        pkg_hash = hashlib.sha256(manifest_str.encode()).hexdigest()

        return EvidencePackage(
            package_id           = str(uuid.uuid4())[:8],
            audit_name           = collector.audit_name,
            prepared_by          = self._preparer,
            prepared_at          = datetime.now(timezone.utc).isoformat(),
            audit_period         = audit_period,
            total_artefacts      = len(artefacts),
            total_controls       = total,
            satisfied_controls   = satisfied_n,
            outstanding_controls = total - satisfied_n,
            coverage_pct         = cov_pct,
            artefacts            = arts_dict,
            control_coverage     = coverage,
            framework_summary    = framework_data,
            package_hash         = pkg_hash,
        )
