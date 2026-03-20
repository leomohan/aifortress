"""
drift_detector.py  —  IaC vs deployed state drift detection
AI Fortress · Chapter 7 · Code Sample 7.A

Compares a "golden" IaC state snapshot (from Terraform state or a
serialised representation of the declared infrastructure) with the
live deployed infrastructure state.

Three drift categories:
  SHADOW  — resources present in deployed state but not in IaC
             (manually created, bypassing code review and policy checks)
  CHANGED — resources in both states but with differing configuration
             (manual changes after deployment overriding secure defaults)
  MISSING — resources in IaC but not in deployed state
             (deletion or provisioning failure)

Input format:
  Both states are dicts of the form:
    { "resource_type.resource_name": { ...attributes... }, ... }
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class DriftItem:
    drift_type:    str          # "SHADOW" | "CHANGED" | "MISSING"
    resource_id:   str          # "resource_type.resource_name"
    severity:      str          # "HIGH" (SHADOW/CHANGED) | "MEDIUM" (MISSING)
    description:   str
    iac_value:     Optional[Any] = None
    deployed_value: Optional[Any] = None
    changed_fields: List[str]  = field(default_factory=list)


@dataclass
class DriftReport:
    total_drift:   int
    shadow:        int
    changed:       int
    missing:       int
    items:         List[DriftItem]
    clean:         bool     # True if no drift detected

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        if self.clean:
            return "✅ No infrastructure drift detected."
        return (
            f"❌ Drift detected: {self.shadow} shadow, "
            f"{self.changed} changed, {self.missing} missing resources."
        )


class DriftDetector:
    """
    Detects drift between declared IaC state and live deployed state.

    Parameters
    ----------
    ignore_fields : Attribute names to exclude from change comparison
                    (e.g. timestamps, auto-generated IDs).
    """

    def __init__(self, ignore_fields: Optional[List[str]] = None):
        self.ignore_fields = set(ignore_fields or [
            "arn", "id", "creation_date", "last_modified",
            "created_at", "updated_at", "tags_all",
        ])

    def detect(
        self,
        iac_state:      Dict[str, dict],
        deployed_state: Dict[str, dict],
    ) -> DriftReport:
        """
        Compare `iac_state` and `deployed_state`.

        Parameters
        ----------
        iac_state      : Dict from IaC (Terraform state / declared config)
        deployed_state : Dict from live infrastructure describe API
        """
        iac_keys      = set(iac_state.keys())
        deployed_keys = set(deployed_state.keys())
        items: List[DriftItem] = []

        # SHADOW: in deployed but not in IaC
        for rid in deployed_keys - iac_keys:
            items.append(DriftItem(
                drift_type     = "SHADOW",
                resource_id    = rid,
                severity       = "HIGH",
                description    = (
                    f"Resource '{rid}' exists in the deployed environment but is NOT "
                    "declared in IaC. This is likely a manual (shadow) change that "
                    "bypassed code review and security policy gates."
                ),
                deployed_value = deployed_state[rid],
            ))

        # MISSING: in IaC but not in deployed
        for rid in iac_keys - deployed_keys:
            items.append(DriftItem(
                drift_type = "MISSING",
                resource_id = rid,
                severity   = "MEDIUM",
                description = (
                    f"Resource '{rid}' is declared in IaC but NOT present "
                    "in the deployed environment. Possible provisioning failure "
                    "or accidental deletion."
                ),
                iac_value   = iac_state[rid],
            ))

        # CHANGED: in both but with different attribute values
        for rid in iac_keys & deployed_keys:
            iac_attrs      = iac_state[rid]
            deployed_attrs = deployed_state[rid]
            changed        = self._diff_attrs(iac_attrs, deployed_attrs)
            if changed:
                items.append(DriftItem(
                    drift_type     = "CHANGED",
                    resource_id    = rid,
                    severity       = "HIGH",
                    description    = (
                        f"Resource '{rid}' has drifted: {len(changed)} attribute(s) "
                        "differ between IaC declaration and deployed state. "
                        "Manual changes may have overridden security configurations."
                    ),
                    iac_value      = {k: iac_attrs.get(k) for k in changed},
                    deployed_value = {k: deployed_attrs.get(k) for k in changed},
                    changed_fields = changed,
                ))

        shadow  = sum(1 for i in items if i.drift_type == "SHADOW")
        changed = sum(1 for i in items if i.drift_type == "CHANGED")
        missing = sum(1 for i in items if i.drift_type == "MISSING")

        return DriftReport(
            total_drift = len(items),
            shadow      = shadow,
            changed     = changed,
            missing     = missing,
            items       = items,
            clean       = len(items) == 0,
        )

    def load_state_file(self, path: str | Path) -> Dict[str, dict]:
        """Load a state JSON file (flat resource_id → attributes dict)."""
        return json.loads(Path(path).read_text(encoding="utf-8"))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _diff_attrs(self, iac: dict, deployed: dict) -> List[str]:
        """Return list of attribute names that differ (excluding ignored fields)."""
        all_keys = set(iac.keys()) | set(deployed.keys())
        changed  = []
        for k in all_keys:
            if k in self.ignore_fields:
                continue
            if iac.get(k) != deployed.get(k):
                changed.append(k)
        return sorted(changed)
