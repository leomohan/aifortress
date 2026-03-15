"""
pam_audit_trail.py  —  Tamper-evident PAM audit trail
AI Fortress · Chapter 11 · Code Sample 11.B

SHA-256 hash-chained JSON Lines log for all PAM events.
Uses the same chaining pattern as SecurityAuditLogger (Ch.09-A).

Event types logged:
  jit_requested | jit_approved | jit_denied | jit_activated
  jit_revoked   | jit_expired
  credential_checked_out | credential_checked_in | credential_auto_released
  session_started | session_closed
  access_denied
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class PAMEvent:
    event_id:   str
    ts:         str
    event_type: str
    principal:  str
    operation:  str
    resource:   str
    detail:     str
    success:    bool
    prev_hash:  str
    self_hash:  str


class PAMAuditTrail:
    """
    Tamper-evident PAM audit trail.

    Parameters
    ----------
    log_path : Path to the JSON Lines log file.
    """

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

    def log(
        self,
        event_type: str,
        principal:  str,
        operation:  str,
        resource:   str = "",
        detail:     str = "",
        success:    bool = True,
    ) -> PAMEvent:
        data = {
            "event_id":   str(uuid.uuid4()),
            "ts":         datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "principal":  principal,
            "operation":  operation,
            "resource":   resource,
            "detail":     detail,
            "success":    success,
            "prev_hash":  self._prev_hash,
        }
        self_hash = hashlib.sha256(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()
        data["self_hash"] = self_hash
        self._prev_hash   = self_hash

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")

        return PAMEvent(**data)

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

    def read_events(self) -> List[PAMEvent]:
        if not self._path.exists():
            return []
        events = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    events.append(PAMEvent(**json.loads(line)))
                except Exception:
                    pass
        return events

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
