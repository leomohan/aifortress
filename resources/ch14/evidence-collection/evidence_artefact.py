"""
evidence_artefact.py  —  Compliance evidence artefact inventory
AI Fortress · Chapter 14 · Code Sample 14.A

Maintains an inventory of compliance evidence artefacts — documents,
logs, test results, screenshots, and configuration exports — that
demonstrate a control is operating effectively.

Each artefact is SHA-256 hashed on ingestion to guarantee integrity.
Artefacts are tagged with the control(s) they satisfy and the audit
period to which they belong.

Evidence types:
  policy_document | procedure_document | test_result | log_export |
  configuration_export | training_record | audit_report | attestation |
  risk_assessment | screenshot | tool_output
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class EvidenceArtefact:
    artefact_id:   str
    title:         str
    evidence_type: str
    control_ids:   List[str]      # controls this artefact satisfies
    audit_period:  str            # e.g. "2025-Q4", "2026-01"
    sha256:        str            # integrity hash
    size_bytes:    int
    collected_by:  str
    collected_at:  str
    description:   str
    tags:          List[str]
    status:        str            # "active" | "superseded" | "archived"


@dataclass
class EvidenceInventory:
    audit_name:   str
    artefacts:    List[EvidenceArtefact]
    control_coverage: Dict[str, int]   # control_id → count of artefacts
    generated_at: str

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class EvidenceCollector:
    """
    Collects and inventories compliance evidence artefacts.

    Parameters
    ----------
    audit_name     : Name of the audit or assessment this evidence supports.
    collector_name : Name of the person or system collecting evidence.
    storage_path   : Optional JSON Lines path for persistent evidence log.
    """

    def __init__(
        self,
        audit_name:     str,
        collector_name: str = "system",
        storage_path:   Optional[str | Path] = None,
    ):
        self.audit_name     = audit_name
        self._collector     = collector_name
        self._artefacts:    List[EvidenceArtefact] = []
        self._path          = Path(storage_path) if storage_path else None
        if self._path and self._path.exists():
            self._load()

    def collect(
        self,
        content:       bytes,
        title:         str,
        evidence_type: str,
        control_ids:   List[str],
        audit_period:  str,
        description:   str = "",
        tags:          Optional[List[str]] = None,
    ) -> EvidenceArtefact:
        """
        Hash and register a piece of compliance evidence.

        Parameters
        ----------
        content       : Raw bytes of the evidence artefact.
        title         : Human-readable title.
        evidence_type : One of the evidence type constants.
        control_ids   : List of control IDs this artefact satisfies.
        audit_period  : Audit period string (e.g. "2026-Q1").
        """
        sha = hashlib.sha256(content).hexdigest()
        art = EvidenceArtefact(
            artefact_id   = str(uuid.uuid4())[:8],
            title         = title,
            evidence_type = evidence_type,
            control_ids   = list(control_ids),
            audit_period  = audit_period,
            sha256        = sha,
            size_bytes    = len(content),
            collected_by  = self._collector,
            collected_at  = datetime.now(timezone.utc).isoformat(),
            description   = description,
            tags          = list(tags or []),
            status        = "active",
        )
        self._artefacts.append(art)
        if self._path:
            self._append(art)
        return art

    def supersede(self, artefact_id: str, reason: str) -> None:
        """Mark an artefact as superseded by newer evidence."""
        for a in self._artefacts:
            if a.artefact_id == artefact_id:
                a.status = "superseded"
                a.tags.append(f"superseded:{reason}")
                if self._path:
                    self._rewrite()
                return
        raise KeyError(f"Artefact '{artefact_id}' not found")

    def for_control(self, control_id: str) -> List[EvidenceArtefact]:
        """Return all active artefacts for a given control ID."""
        return [
            a for a in self._artefacts
            if control_id in a.control_ids and a.status == "active"
        ]

    def inventory(self) -> EvidenceInventory:
        """Build a coverage inventory across all controls."""
        coverage: Dict[str, int] = {}
        for a in self._artefacts:
            if a.status == "active":
                for c in a.control_ids:
                    coverage[c] = coverage.get(c, 0) + 1
        return EvidenceInventory(
            audit_name       = self.audit_name,
            artefacts        = list(self._artefacts),
            control_coverage = coverage,
            generated_at     = datetime.now(timezone.utc).isoformat(),
        )

    def verify_integrity(self, artefact_id: str, content: bytes) -> bool:
        """Re-hash content and compare against stored SHA-256."""
        for a in self._artefacts:
            if a.artefact_id == artefact_id:
                return hashlib.sha256(content).hexdigest() == a.sha256
        raise KeyError(f"Artefact '{artefact_id}' not found")

    def uncovered_controls(self, required_controls: List[str]) -> List[str]:
        """Return controls from required_controls with zero active artefacts."""
        covered = {
            c for a in self._artefacts if a.status == "active"
            for c in a.control_ids
        }
        return [c for c in required_controls if c not in covered]

    def _append(self, art: EvidenceArtefact) -> None:
        import dataclasses
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a") as f:
            f.write(json.dumps(dataclasses.asdict(art)) + "\n")

    def _rewrite(self) -> None:
        import dataclasses
        self._path.write_text(
            "\n".join(json.dumps(dataclasses.asdict(a)) for a in self._artefacts)
            + "\n"
        )

    def _load(self) -> None:
        lines = self._path.read_text().strip().splitlines()
        self._artefacts = [EvidenceArtefact(**json.loads(l)) for l in lines if l.strip()]
