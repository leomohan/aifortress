"""
action_tracker.py  —  Postmortem action item tracker
AI Fortress · Chapter 17 · Code Sample 17.C

Tracks corrective and preventive action items arising from
incident postmortems. Integrates with finding IDs so each
action can be traced to the finding it addresses.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class ActionItem:
    action_id:   str
    finding_id:  Optional[str]
    title:       str
    description: str
    owner:       str
    due_date:    str
    priority:    str     # "P1"|"P2"|"P3"
    status:      str     # "open"|"in_progress"|"done"|"cancelled"
    created_at:  str
    closed_at:   Optional[str] = None


class ActionTracker:
    """Tracks postmortem action items with priority and owner."""

    def __init__(self, incident_id: str, storage_path: Optional[str | Path] = None):
        self.incident_id = incident_id
        self._items:     List[ActionItem] = []
        self._path       = Path(storage_path) if storage_path else None

    def add(
        self,
        title:       str,
        description: str,
        owner:       str,
        due_date:    str,
        priority:    str = "P2",
        finding_id:  Optional[str] = None,
    ) -> ActionItem:
        item = ActionItem(
            action_id   = str(uuid.uuid4())[:8],
            finding_id  = finding_id,
            title       = title,
            description = description,
            owner       = owner,
            due_date    = due_date,
            priority    = priority,
            status      = "open",
            created_at  = datetime.now(timezone.utc).isoformat(),
        )
        self._items.append(item)
        if self._path:
            self._save()
        return item

    def update_status(self, action_id: str, status: str) -> None:
        for item in self._items:
            if item.action_id == action_id:
                item.status = status
                if status in ("done", "cancelled"):
                    item.closed_at = datetime.now(timezone.utc).isoformat()
                if self._path:
                    self._save()
                return
        raise KeyError(f"Action '{action_id}' not found")

    def open_items(self) -> List[ActionItem]:
        return [i for i in self._items if i.status in ("open", "in_progress")]

    def overdue_items(self) -> List[ActionItem]:
        now = datetime.now(timezone.utc).isoformat()
        return [
            i for i in self.open_items()
            if i.due_date < now
        ]

    def items(self) -> List[ActionItem]:
        return list(self._items)

    def _save(self) -> None:
        import dataclasses
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([dataclasses.asdict(i) for i in self._items], indent=2)
        )
