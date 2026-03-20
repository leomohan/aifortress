"""
rollback_guard.py  —  OTA rollback prevention for edge devices
AI Fortress · Chapter 15 · Code Sample 15.C

Prevents rollback attacks (downgrade via OTA) by maintaining a
monotonic version counter in protected storage (simulating Anti-Rollback
Counter stored in eFuse or TPM NV index).

Rules:
  - New package version must be > recorded minimum version
  - After successful install, the minimum version counter advances
  - Counter only ever increases; it cannot be reset without hardware access
  - Emergency rollback requires explicit operator override with audit log
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class RollbackCheckResult:
    allowed:          bool
    current_minimum:  str
    requested_version: str
    reason:           str


@dataclass
class RollbackCounterRecord:
    minimum_version: str
    updated_at:      str
    updated_by:      str
    override:        bool = False


class RollbackGuard:
    """
    Monotonic rollback prevention for OTA updates.

    Parameters
    ----------
    storage_path  : Path to JSON file simulating protected NV storage.
    initial_version : Starting minimum version (set at provisioning).
    """

    def __init__(
        self,
        storage_path:    str | Path,
        initial_version: str = "0.0.0",
    ):
        self._path    = Path(storage_path)
        self._history: List[RollbackCounterRecord] = []
        self._minimum = initial_version

        if self._path.exists():
            self._load()

    @property
    def minimum_version(self) -> str:
        return self._minimum

    def check(self, target_version: str) -> RollbackCheckResult:
        """Check whether target_version is allowed (must be > minimum)."""
        allowed = self._ver_gt(target_version, self._minimum)
        return RollbackCheckResult(
            allowed           = allowed,
            current_minimum   = self._minimum,
            requested_version = target_version,
            reason            = (
                "Version allowed." if allowed
                else f"Rollback blocked: {target_version} <= minimum {self._minimum}."
            ),
        )

    def advance(self, new_version: str, updated_by: str = "ota-daemon") -> None:
        """Advance the minimum version after a successful update."""
        if not self._ver_gt(new_version, self._minimum):
            raise ValueError(
                f"Cannot advance counter: {new_version} is not > current minimum {self._minimum}"
            )
        self._minimum = new_version
        record = RollbackCounterRecord(
            minimum_version = new_version,
            updated_at      = datetime.now(timezone.utc).isoformat(),
            updated_by      = updated_by,
        )
        self._history.append(record)
        self._save()

    def emergency_override(
        self,
        allow_version: str,
        authorised_by: str,
        reason:        str,
    ) -> RollbackCounterRecord:
        """
        Temporarily allow a lower version (emergency fix).
        Requires explicit authorisation; records override in audit log.
        Emergency overrides do NOT lower the counter permanently.
        """
        record = RollbackCounterRecord(
            minimum_version = allow_version,
            updated_at      = datetime.now(timezone.utc).isoformat(),
            updated_by      = f"OVERRIDE:{authorised_by}:{reason}",
            override        = True,
        )
        self._history.append(record)
        self._save()
        return record

    def history(self) -> List[RollbackCounterRecord]:
        return list(self._history)

    def _ver_gt(self, a: str, b: str) -> bool:
        """Return True if version a > version b (simple numeric comparison)."""
        def parse(v):
            try:
                return tuple(int(x) for x in v.split(".")[:3])
            except ValueError:
                return (0, 0, 0)
        return parse(a) > parse(b)

    def _save(self) -> None:
        import dataclasses
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "minimum_version": self._minimum,
            "history": [dataclasses.asdict(r) for r in self._history],
        }
        self._path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        data = json.loads(self._path.read_text())
        self._minimum = data.get("minimum_version", "0.0.0")
        self._history = [
            RollbackCounterRecord(**r) for r in data.get("history", [])
        ]
