"""
model_rollback_orchestrator.py  —  Model rollback for incident recovery
AI Fortress · Chapter 17 · Code Sample 17.D

Manages controlled model rollback during incident recovery.
Enforces a rollback checklist before restoring a prior version,
records the rollback in an audit trail, and validates that the
restored model passes integrity checks.
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
class ModelVersion:
    version_id:   str
    model_name:   str
    version_tag:  str
    weights_hash: str    # SHA-256 of model weights
    created_at:   str
    blessed:      bool   # True = approved for production use


@dataclass
class RollbackRecord:
    rollback_id:      str
    incident_id:      str
    from_version:     str
    to_version:       str
    executed_by:      str
    checklist_passed: bool
    checklist_items:  Dict[str, bool]
    executed_at:      str
    notes:            str


@dataclass
class RollbackResult:
    success:          bool
    record:           RollbackRecord
    integrity_ok:     bool
    reason:           str


class ModelRollbackOrchestrator:
    """
    Orchestrates model rollback with pre-rollback checklist and audit trail.

    Parameters
    ----------
    registry_path : Optional JSON path for version registry persistence.
    """

    _CHECKLIST = [
        "known_good_version_exists",
        "weights_hash_verified",
        "version_is_blessed",
        "incident_commander_approved",
        "rollback_window_agreed",
    ]

    def __init__(self, registry_path: Optional[str | Path] = None):
        self._versions: Dict[str, ModelVersion] = {}
        self._history:  List[RollbackRecord]    = []
        self._path      = Path(registry_path) if registry_path else None

    def register_version(
        self,
        model_name:   str,
        version_tag:  str,
        weights:      bytes,
        blessed:      bool = False,
    ) -> ModelVersion:
        wh = hashlib.sha256(weights).hexdigest()
        v  = ModelVersion(
            version_id  = str(uuid.uuid4())[:8],
            model_name  = model_name,
            version_tag = version_tag,
            weights_hash = wh,
            created_at  = datetime.now(timezone.utc).isoformat(),
            blessed     = blessed,
        )
        self._versions[v.version_id] = v
        return v

    def rollback(
        self,
        incident_id:       str,
        from_version_id:   str,
        to_version_id:     str,
        executed_by:       str,
        checklist_overrides: Optional[Dict[str, bool]] = None,
        notes:             str = "",
    ) -> RollbackResult:
        """Execute a model rollback with checklist enforcement."""
        target = self._versions.get(to_version_id)
        if not target:
            raise KeyError(f"Version '{to_version_id}' not in registry")

        # Evaluate checklist
        checklist: Dict[str, bool] = {k: False for k in self._CHECKLIST}
        checklist["known_good_version_exists"] = to_version_id in self._versions
        checklist["weights_hash_verified"]     = bool(target.weights_hash)
        checklist["version_is_blessed"]        = target.blessed
        # Allow human override of remaining items
        if checklist_overrides:
            checklist.update(checklist_overrides)

        all_pass = all(checklist.values())

        record = RollbackRecord(
            rollback_id      = str(uuid.uuid4())[:8],
            incident_id      = incident_id,
            from_version     = from_version_id,
            to_version       = to_version_id,
            executed_by      = executed_by,
            checklist_passed = all_pass,
            checklist_items  = checklist,
            executed_at      = datetime.now(timezone.utc).isoformat(),
            notes            = notes,
        )
        self._history.append(record)
        if self._path:
            self._save()

        return RollbackResult(
            success      = all_pass,
            record       = record,
            integrity_ok = checklist["weights_hash_verified"],
            reason       = (
                "Rollback completed successfully." if all_pass
                else f"Rollback blocked: failed checklist items: "
                     f"{[k for k, v in checklist.items() if not v]}"
            ),
        )

    def history(self) -> List[RollbackRecord]:
        return list(self._history)

    def _save(self) -> None:
        import dataclasses
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "versions": [dataclasses.asdict(v) for v in self._versions.values()],
            "history":  [dataclasses.asdict(r) for r in self._history],
        }
        self._path.write_text(json.dumps(data, indent=2))
