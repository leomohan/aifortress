"""
rollback_audit_trail.py  —  Tamper-evident rollback audit log
AI Fortress · Chapter 12 · Code Sample 12.C

SHA-256 hash-chained JSON Lines log for all rollback attempts.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class RollbackAuditEntry:
    entry_id:       str
    ts:             str
    model_name:     str
    from_version:   str
    to_version:     str
    success:        bool
    reverted:       bool
    executed_by:    str
    reason:         str
    checks_failed:  List[str]
    prev_hash:      str
    self_hash:      str


class RollbackAuditTrail:
    """Tamper-evident rollback audit trail using SHA-256 hash chaining."""

    def __init__(self, log_path: str | Path):
        self._path      = Path(log_path)
        self._prev_hash = "0" * 64
        if self._path.exists():
            try:
                last = self._last_line()
                if last:
                    self._prev_hash = json.loads(last).get("self_hash", "0" * 64)
            except Exception:
                pass

    def log(self, outcome) -> RollbackAuditEntry:
        data = {
            "entry_id":      str(uuid.uuid4()),
            "ts":            datetime.now(timezone.utc).isoformat(),
            "model_name":    outcome.model_name,
            "from_version":  outcome.from_version,
            "to_version":    outcome.to_version,
            "success":       outcome.success,
            "reverted":      outcome.reverted,
            "executed_by":   outcome.executed_by,
            "reason":        outcome.reason,
            "checks_failed": outcome.eligibility.checks_failed,
            "prev_hash":     self._prev_hash,
        }
        self_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()
        data["self_hash"] = self_hash
        self._prev_hash   = self_hash

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")

        return RollbackAuditEntry(**data)

    def verify_chain(self) -> bool:
        if not self._path.exists():
            return True
        prev = "0" * 64
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False
            if entry.get("prev_hash") != prev:
                return False
            check    = {k: v for k, v in entry.items() if k != "self_hash"}
            expected = hashlib.sha256(
                json.dumps(check, sort_keys=True).encode()
            ).hexdigest()
            if entry.get("self_hash") != expected:
                return False
            prev = entry["self_hash"]
        return True

    def read_entries(self) -> List[RollbackAuditEntry]:
        if not self._path.exists():
            return []
        entries = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    entries.append(RollbackAuditEntry(**json.loads(line)))
                except Exception:
                    pass
        return entries

    def _last_line(self) -> str:
        with open(self._path, "rb") as f:
            f.seek(0, 2)
            if f.tell() == 0:
                return ""
            buf, pos = b"", f.tell() - 1
            while pos >= 0:
                f.seek(pos)
                ch = f.read(1)
                if ch == b"\n" and buf:
                    break
                buf = ch + buf
                pos -= 1
        return buf.decode("utf-8", errors="ignore").strip()
