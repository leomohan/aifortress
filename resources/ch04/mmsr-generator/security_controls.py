"""
security_controls.py  —  Security control attestation registry
AI Fortress · Chapter 4 · Code Sample 4.C
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class ControlAttestation:
    control_name:  str
    active:        bool
    evidence_ref:  str = ""
    notes:         str = ""
    attested_at:   str = ""

    def __post_init__(self):
        if not self.attested_at:
            self.attested_at = datetime.now(timezone.utc).isoformat()


# The 10 Chapter 4 security controls
CHAPTER4_CONTROLS = [
    "secrets_manager",
    "network_isolation",
    "gpu_hygiene",
    "workspace_isolation",
    "reproducibility_lock",
    "loss_spike_detection",
    "gradient_norm_monitoring",
    "lr_schedule_auditing",
    "checkpoint_integrity",
    "telemetry_aggregation",
]


class SecurityControlsEvidence:
    def __init__(self, job_id: str):
        self.job_id       = job_id
        self._attestations: Dict[str, ControlAttestation] = {}

    def attest(
        self,
        control_name: str,
        active:       bool,
        evidence_ref: str = "",
        notes:        str = "",
    ) -> ControlAttestation:
        a = ControlAttestation(
            control_name = control_name,
            active       = active,
            evidence_ref = evidence_ref,
            notes        = notes,
        )
        self._attestations[control_name] = a
        return a

    def unattest(self) -> List[str]:
        """Return controls from the Chapter 4 list that have NOT been attested."""
        return [c for c in CHAPTER4_CONTROLS if c not in self._attestations]

    def coverage_score(self) -> float:
        """Fraction of Chapter 4 controls that are active."""
        active = sum(1 for a in self._attestations.values() if a.active)
        return active / len(CHAPTER4_CONTROLS)

    def to_list(self) -> List[dict]:
        return [asdict(a) for a in self._attestations.values()]
