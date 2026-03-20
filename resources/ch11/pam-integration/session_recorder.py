"""
session_recorder.py  —  Privileged session metadata recording
AI Fortress · Chapter 11 · Code Sample 11.B

Records metadata for all privileged ML sessions for compliance and
incident investigation.

Records captured per session:
  - Session ID, principal, operation, resource
  - Start / end timestamps
  - Approval chain (request_id, approver)
  - Commands / API calls executed (stub — replace with real capture)
  - Termination reason (normal | timeout | revoked | exception)
  - Session integrity hash (SHA-256 of session record)
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
class SessionRecord:
    session_id:    str
    principal:     str
    operation:     str
    resource:      str
    request_id:    str            # JIT request that authorised this session
    approver:      str
    started_at:    str
    ended_at:      str = ""
    duration_secs: float = 0.0
    termination:   str  = ""      # "normal" | "timeout" | "revoked" | "exception"
    commands:      List[str] = field(default_factory=list)
    record_hash:   str = ""       # set on close()

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


class SessionRecorder:
    """
    Records privileged session metadata.

    Parameters
    ----------
    sessions_path : Optional JSON Lines path to persist session records.
    """

    def __init__(self, sessions_path: Optional[str | Path] = None):
        self._sessions: Dict[str, SessionRecord] = {}
        self._path = Path(sessions_path) if sessions_path else None

    def start(
        self,
        principal:  str,
        operation:  str,
        resource:   str,
        request_id: str,
        approver:   str,
    ) -> SessionRecord:
        """Start recording a privileged session."""
        session = SessionRecord(
            session_id  = str(uuid.uuid4()),
            principal   = principal,
            operation   = operation,
            resource    = resource,
            request_id  = request_id,
            approver    = approver,
            started_at  = datetime.now(timezone.utc).isoformat(),
        )
        self._sessions[session.session_id] = session
        return session

    def record_command(self, session_id: str, command: str) -> None:
        """Append a command/API-call record to the session."""
        session = self._sessions.get(session_id)
        if session:
            # Truncate to avoid enormous logs; in production use streaming
            session.commands.append(command[:512])

    def close(
        self,
        session_id:  str,
        termination: str = "normal",
    ) -> Optional[SessionRecord]:
        """Close a session and compute its integrity hash."""
        session = self._sessions.get(session_id)
        if session is None:
            return None

        ended              = datetime.now(timezone.utc)
        session.ended_at   = ended.isoformat()
        session.termination = termination

        started = datetime.fromisoformat(session.started_at)
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        session.duration_secs = round((ended - started).total_seconds(), 2)

        # Compute integrity hash (excluding record_hash itself)
        d     = session.to_dict()
        d.pop("record_hash", None)
        session.record_hash = hashlib.sha256(
            json.dumps(d, sort_keys=True).encode()
        ).hexdigest()

        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(session.to_dict()) + "\n")

        return session

    def get(self, session_id: str) -> Optional[SessionRecord]:
        return self._sessions.get(session_id)

    def active_sessions(self) -> List[SessionRecord]:
        return [s for s in self._sessions.values() if not s.ended_at]


# ─────────────────────────────────────────────────────────────────────────────

"""
pam_audit_trail.py  —  Tamper-evident PAM audit trail
AI Fortress · Chapter 11 · Code Sample 11.B

SHA-256 hash-chained JSON Lines log for all PAM events.
Uses the same chaining pattern as SecurityAuditLogger (Ch.09-A).
"""


import hashlib as _hashlib
import json as _json
import uuid as _uuid
from dataclasses import dataclass as _dataclass
from datetime import datetime as _datetime, timezone as _timezone
from pathlib import Path as _Path
from typing import List as _List, Optional as _Optional


@_dataclass
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

    def __init__(self, log_path: str | _Path):
        self._path      = _Path(log_path)
        self._prev_hash = "0" * 64
        if self._path.exists():
            try:
                last = self._last_line()
                if last:
                    self._prev_hash = _json.loads(last).get("self_hash", "0" * 64)
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
            "event_id":   str(_uuid.uuid4()),
            "ts":         _datetime.now(_timezone.utc).isoformat(),
            "event_type": event_type,
            "principal":  principal,
            "operation":  operation,
            "resource":   resource,
            "detail":     detail,
            "success":    success,
            "prev_hash":  self._prev_hash,
        }
        self_hash = _hashlib.sha256(
            _json.dumps(data, sort_keys=True).encode()
        ).hexdigest()
        data["self_hash"] = self_hash
        self._prev_hash   = self_hash

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(_json.dumps(data) + "\n")

        return PAMEvent(**data)

    def verify_chain(self) -> bool:
        if not self._path.exists():
            return True
        prev = "0" * 64
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = _json.loads(line)
            except _json.JSONDecodeError:
                return False
            if entry.get("prev_hash") != prev:
                return False
            check = {k: v for k, v in entry.items() if k != "self_hash"}
            expected = _hashlib.sha256(
                _json.dumps(check, sort_keys=True).encode()
            ).hexdigest()
            if entry.get("self_hash") != expected:
                return False
            prev = entry["self_hash"]
        return True

    def read_events(self) -> _List[PAMEvent]:
        if not self._path.exists():
            return []
        events = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    events.append(PAMEvent(**_json.loads(line)))
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
