"""
data_quarantine_manager.py  —  Data quarantine for incident containment/recovery
AI Fortress · Chapter 17 · Code Sample 17.D

Manages quarantine of potentially poisoned or exfiltrated datasets.
Tracks which data partitions are under quarantine, who authorised it,
and the reason. Prevents quarantined data from re-entering training
pipelines until cleared.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class QuarantineEntry:
    quarantine_id: str
    dataset_id:    str
    reason:        str
    authorised_by: str
    quarantined_at: str
    cleared_at:    Optional[str] = None
    cleared_by:    Optional[str] = None
    active:        bool = True


@dataclass
class QuarantineCheckResult:
    dataset_id:    str
    quarantined:   bool
    entry:         Optional[QuarantineEntry]
    reason:        str


class DataQuarantineManager:
    """Manages dataset quarantine during incident containment and recovery."""

    def __init__(self, storage_path: Optional[str | Path] = None):
        self._entries: List[QuarantineEntry] = []
        self._path    = Path(storage_path) if storage_path else None

    def quarantine(
        self,
        dataset_id:    str,
        reason:        str,
        authorised_by: str,
    ) -> QuarantineEntry:
        # Check not already quarantined
        if self.check(dataset_id).quarantined:
            raise ValueError(f"Dataset '{dataset_id}' is already quarantined")
        entry = QuarantineEntry(
            quarantine_id  = str(uuid.uuid4())[:8],
            dataset_id     = dataset_id,
            reason         = reason,
            authorised_by  = authorised_by,
            quarantined_at = datetime.now(timezone.utc).isoformat(),
        )
        self._entries.append(entry)
        if self._path:
            self._save()
        return entry

    def clear(
        self,
        dataset_id: str,
        cleared_by: str,
    ) -> QuarantineEntry:
        for e in self._entries:
            if e.dataset_id == dataset_id and e.active:
                e.active     = False
                e.cleared_at = datetime.now(timezone.utc).isoformat()
                e.cleared_by = cleared_by
                if self._path:
                    self._save()
                return e
        raise KeyError(f"No active quarantine for dataset '{dataset_id}'")

    def check(self, dataset_id: str) -> QuarantineCheckResult:
        active = next(
            (e for e in self._entries if e.dataset_id == dataset_id and e.active),
            None,
        )
        return QuarantineCheckResult(
            dataset_id  = dataset_id,
            quarantined = active is not None,
            entry       = active,
            reason      = active.reason if active else "Not quarantined",
        )

    def active_quarantines(self) -> List[QuarantineEntry]:
        return [e for e in self._entries if e.active]

    def _save(self) -> None:
        import dataclasses
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(
            [dataclasses.asdict(e) for e in self._entries], indent=2
        ))
