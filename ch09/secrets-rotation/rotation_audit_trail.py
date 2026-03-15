"""
rotation_audit_trail.py  —  Structured rotation audit trail
AI Fortress · Chapter 9 · Code Sample 9.C

Records all secret rotation events in a tamper-evident JSON Lines log.
Uses the same hash-chaining approach as SecurityAuditLogger (9.A) for
consistency across the ML platform audit infrastructure.

Event types:
  credential_rotated  — database credential rotation completed
  credential_failed   — rotation attempted but smoke test failed
  api_key_rotated     — external API key rotated
  api_key_expiry      — expiry alert for an API key
  cert_renewed        — certificate renewed (ACME or SPIRE)
  cert_expiry         — expiry alert for a certificate
  rotation_scheduled  — rotation job scheduled for future execution
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class RotationEvent:
    event_id:   str
    ts:         str
    event_type: str
    service:    str
    secret_type: str     # "credential" | "api_key" | "certificate"
    detail:     str
    success:    bool
    metadata:   Dict[str, Any]
    prev_hash:  str
    self_hash:  str


class RotationAuditTrail:
    """
    Tamper-evident rotation event log.

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

    def log_rotation(
        self,
        service:     str,
        secret_type: str,
        detail:      str = "",
        success:     bool = True,
        metadata:    Optional[Dict] = None,
    ) -> RotationEvent:
        event_type = f"{secret_type}_rotated" if success else f"{secret_type}_failed"
        return self._write(event_type, service, secret_type, detail, success, metadata or {})

    def log_expiry_alert(
        self,
        service:     str,
        secret_type: str,
        detail:      str,
        severity:    str,
    ) -> RotationEvent:
        return self._write(
            f"{secret_type}_expiry", service, secret_type, detail, True,
            {"severity": severity},
        )

    def log_scheduled(
        self,
        service:      str,
        secret_type:  str,
        scheduled_at: str,
    ) -> RotationEvent:
        return self._write(
            "rotation_scheduled", service, secret_type,
            f"Rotation scheduled for {scheduled_at}", True,
            {"scheduled_at": scheduled_at},
        )

    def read_events(self) -> List[RotationEvent]:
        if not self._path.exists():
            return []
        events = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    events.append(RotationEvent(**json.loads(line)))
                except Exception:
                    pass
        return events

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire log chain."""
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
            check = {k: v for k, v in entry.items() if k != "self_hash"}
            expected = hashlib.sha256(
                json.dumps(check, sort_keys=True).encode()
            ).hexdigest()
            if entry.get("self_hash") != expected:
                return False
            prev = entry["self_hash"]
        return True

    # ── Internal ──────────────────────────────────────────────────────────────

    def _write(
        self,
        event_type:  str,
        service:     str,
        secret_type: str,
        detail:      str,
        success:     bool,
        metadata:    Dict,
    ) -> RotationEvent:
        data = {
            "event_id":   str(uuid.uuid4()),
            "ts":         datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "service":    service,
            "secret_type": secret_type,
            "detail":     detail,
            "success":    success,
            "metadata":   metadata,
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

        return RotationEvent(**data)

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
