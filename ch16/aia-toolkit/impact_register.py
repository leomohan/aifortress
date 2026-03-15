"""
impact_register.py  —  Algorithmic Impact Assessment register
AI Fortress · Chapter 16 · Code Sample 16.C

Maintains a register of AI system impacts — intended, unintended,
direct, and indirect — across affected populations and domains.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class ImpactEntry:
    impact_id:      str
    system_name:    str
    impact_type:    str    # "direct" | "indirect" | "systemic"
    severity:       str    # "critical" | "high" | "moderate" | "low"
    affected_group: str
    description:    str
    likelihood:     int    # 1–5
    magnitude:      int    # 1–5
    risk_score:     int    # likelihood × magnitude
    mitigations:    List[str]
    status:         str    # "open" | "mitigated" | "accepted"
    recorded_at:    str


class ImpactRegister:
    """Maintains the AIA impact register for an AI system."""

    def __init__(self, system_name: str, register_path: Optional[str | Path] = None):
        self.system_name = system_name
        self._entries:   List[ImpactEntry] = []
        self._path       = Path(register_path) if register_path else None
        if self._path and self._path.exists():
            self._load()

    def add(
        self,
        impact_type:    str,
        severity:       str,
        affected_group: str,
        description:    str,
        likelihood:     int,
        magnitude:      int,
        mitigations:    Optional[List[str]] = None,
        status:         str = "open",
    ) -> ImpactEntry:
        entry = ImpactEntry(
            impact_id      = str(uuid.uuid4())[:8],
            system_name    = self.system_name,
            impact_type    = impact_type,
            severity       = severity,
            affected_group = affected_group,
            description    = description,
            likelihood     = max(1, min(5, likelihood)),
            magnitude      = max(1, min(5, magnitude)),
            risk_score     = likelihood * magnitude,
            mitigations    = mitigations or [],
            status         = status,
            recorded_at    = datetime.now(timezone.utc).isoformat(),
        )
        self._entries.append(entry)
        if self._path:
            self._save()
        return entry

    def entries(self, status: Optional[str] = None) -> List[ImpactEntry]:
        if status:
            return [e for e in self._entries if e.status == status]
        return list(self._entries)

    def high_risk_entries(self, threshold: int = 15) -> List[ImpactEntry]:
        return [e for e in self._entries if e.risk_score >= threshold]

    def mitigate(self, impact_id: str, mitigation: str) -> None:
        for e in self._entries:
            if e.impact_id == impact_id:
                e.mitigations.append(mitigation)
                e.status = "mitigated"
                if self._path:
                    self._save()
                return
        raise KeyError(f"Impact '{impact_id}' not found")

    def _save(self) -> None:
        import dataclasses
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([dataclasses.asdict(e) for e in self._entries], indent=2)
        )

    def _load(self) -> None:
        data = json.loads(self._path.read_text())
        self._entries = [ImpactEntry(**d) for d in data]
