"""
api_key_lifecycle.py  —  External API key lifecycle manager
AI Fortress · Chapter 9 · Code Sample 9.C

Tracks API keys for external ML services (HuggingFace, OpenAI, AWS, etc.)
and issues tiered rotation reminders as keys approach expiry.

Reminder thresholds (days before expiry):
  CRITICAL : ≤ 1  day  — rotate immediately
  WARNING  : ≤ 7  days — rotate this week
  INFO     : ≤ 30 days — schedule rotation

Supports manual registration and import from common secret store exports.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional


_THRESHOLDS = [
    (1,  "CRITICAL"),
    (7,  "WARNING"),
    (30, "INFO"),
]


@dataclass
class ExternalKeyEntry:
    key_id:        str
    service:       str        # "huggingface" | "openai" | "aws" | custom
    name:          str        # human-readable key name
    owner:         str
    created_at:    str
    expires_at:    str        # ISO8601 or "" for no expiry
    key_hash:      str        # SHA-256 of the raw key (never stored in clear)
    last_rotated:  str = ""
    notes:         str = ""


@dataclass
class ExpiryAlert:
    key_id:       str
    service:      str
    name:         str
    owner:        str
    expires_at:   str
    days_remaining: int
    severity:     str         # "CRITICAL" | "WARNING" | "INFO"
    message:      str


@dataclass
class LifecycleReport:
    total:    int
    critical: int
    warning:  int
    info:     int
    ok:       int
    no_expiry: int
    alerts:   List[ExpiryAlert]

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.critical == 0 and self.warning == 0 else "❌"
        return (
            f"{icon} API key lifecycle: {self.total} keys, "
            f"{self.critical} CRITICAL, {self.warning} WARNING, "
            f"{self.info} INFO, {self.ok} OK."
        )


class APIKeyLifecycleManager:
    """
    Manages lifecycle of external ML API keys.

    Parameters
    ----------
    state_path : Optional JSON file to persist key registry across runs.
    """

    def __init__(self, state_path: Optional[str | Path] = None):
        self._keys: Dict[str, ExternalKeyEntry] = {}
        self._state_path = Path(state_path) if state_path else None
        if self._state_path and self._state_path.exists():
            self._load()

    def register(
        self,
        service:    str,
        name:       str,
        owner:      str,
        raw_key:    str,
        ttl_days:   Optional[int] = None,
        notes:      str = "",
    ) -> ExternalKeyEntry:
        """Register an external API key. Stores hash only, not raw key."""
        key_id   = str(uuid.uuid4())
        now      = datetime.now(timezone.utc)
        expires  = (now + timedelta(days=ttl_days)).isoformat() if ttl_days else ""
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        entry = ExternalKeyEntry(
            key_id     = key_id,
            service    = service,
            name       = name,
            owner      = owner,
            created_at = now.isoformat(),
            expires_at = expires,
            key_hash   = key_hash,
            notes      = notes,
        )
        self._keys[key_id] = entry
        self._save()
        return entry

    def record_rotation(self, key_id: str, new_raw_key: str) -> None:
        """Update the hash and last_rotated timestamp after a rotation."""
        entry = self._keys.get(key_id)
        if entry is None:
            raise KeyError(f"Key '{key_id}' not found")
        entry.key_hash      = hashlib.sha256(new_raw_key.encode()).hexdigest()
        entry.last_rotated  = datetime.now(timezone.utc).isoformat()
        self._save()

    def deregister(self, key_id: str) -> None:
        """Remove a key from the registry."""
        self._keys.pop(key_id, None)
        self._save()

    def check_expiry(self, now: Optional[datetime] = None) -> LifecycleReport:
        """Scan all registered keys and return a LifecycleReport."""
        now   = now or datetime.now(timezone.utc)
        alerts: List[ExpiryAlert] = []
        counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "OK": 0, "NO_EXPIRY": 0}

        for entry in self._keys.values():
            if not entry.expires_at:
                counts["NO_EXPIRY"] += 1
                continue

            try:
                exp = datetime.fromisoformat(entry.expires_at)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            days_rem = (exp - now).days
            severity = None
            for threshold, sev in _THRESHOLDS:
                if days_rem <= threshold:
                    severity = sev
                    break

            if severity:
                counts[severity] += 1
                alerts.append(ExpiryAlert(
                    key_id        = entry.key_id,
                    service       = entry.service,
                    name          = entry.name,
                    owner         = entry.owner,
                    expires_at    = entry.expires_at,
                    days_remaining = max(0, days_rem),
                    severity      = severity,
                    message       = (
                        f"[{severity}] '{entry.name}' ({entry.service}) expires in "
                        f"{max(0, days_rem)} day(s). Owner: {entry.owner}."
                    ),
                ))
            else:
                counts["OK"] += 1

        return LifecycleReport(
            total     = len(self._keys),
            critical  = counts["CRITICAL"],
            warning   = counts["WARNING"],
            info      = counts["INFO"],
            ok        = counts["OK"],
            no_expiry = counts["NO_EXPIRY"],
            alerts    = sorted(alerts, key=lambda a: a.days_remaining),
        )

    def list_keys(self) -> List[ExternalKeyEntry]:
        return list(self._keys.values())

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self) -> None:
        if not self._state_path:
            return
        import dataclasses
        data = {k: dataclasses.asdict(v) for k, v in self._keys.items()}
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        data = json.loads(self._state_path.read_text(encoding="utf-8"))
        self._keys = {k: ExternalKeyEntry(**v) for k, v in data.items()}
