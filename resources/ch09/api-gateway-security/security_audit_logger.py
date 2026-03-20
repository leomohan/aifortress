"""
security_audit_logger.py  —  Structured audit trail for ML API gateway
AI Fortress · Chapter 9 · Code Sample 9.A

Produces a JSON Lines audit log with tamper-evident hash chaining.
Each log entry includes a SHA-256 hash of the previous entry, forming
a chain that makes retroactive tampering detectable.

Event types logged:
  auth_success | auth_failure | rate_limit | signing_failure
  ip_deny | key_created | key_revoked | key_rotated | key_used
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AuditEvent:
    event_id:    str
    ts:          str
    event_type:  str
    principal:   str
    endpoint:    str
    client_ip:   str
    result:      str          # "success" | "failure" | "deny"
    reason:      str
    metadata:    Dict[str, Any]
    prev_hash:   str          # SHA-256 of previous log line (chain)
    self_hash:   str          # SHA-256 of this entry (excl. self_hash field)


class SecurityAuditLogger:
    """
    Tamper-evident JSON Lines audit logger for ML API gateway events.

    Parameters
    ----------
    log_path  : Path to the JSON Lines log file.
    chain     : If True (default), compute and validate hash chain.
    """

    def __init__(self, log_path: str | Path, chain: bool = True):
        self._path  = Path(log_path)
        self._chain = chain
        self._prev_hash = "0" * 64    # genesis hash

        # If log already exists, recover the last hash for chain continuity
        if self._path.exists():
            try:
                last_line = self._last_line()
                if last_line:
                    self._prev_hash = json.loads(last_line).get("self_hash", "0" * 64)
            except Exception:
                pass

    # ── Log methods ───────────────────────────────────────────────────────────

    def log_auth_success(self, principal: str, endpoint: str, client_ip: str,
                         scopes: List[str] = None) -> AuditEvent:
        return self._write("auth_success", principal, endpoint, client_ip,
                           "success", "Authentication successful",
                           {"scopes": scopes or []})

    def log_auth_failure(self, principal: str, endpoint: str, client_ip: str,
                         reason: str) -> AuditEvent:
        return self._write("auth_failure", principal, endpoint, client_ip,
                           "failure", reason, {})

    def log_rate_limit(self, principal: str, endpoint: str, client_ip: str,
                       limit: int, window_secs: int) -> AuditEvent:
        return self._write("rate_limit", principal, endpoint, client_ip,
                           "deny", "Rate limit exceeded",
                           {"limit": limit, "window_secs": window_secs})

    def log_signing_failure(self, key_id: str, endpoint: str, client_ip: str,
                            reason: str) -> AuditEvent:
        return self._write("signing_failure", key_id, endpoint, client_ip,
                           "failure", reason, {})

    def log_ip_deny(self, client_ip: str, endpoint: str, reason: str,
                    matched_cidr: str = "") -> AuditEvent:
        return self._write("ip_deny", "", endpoint, client_ip,
                           "deny", reason, {"matched_cidr": matched_cidr})

    def log_custom(self, event_type: str, principal: str, endpoint: str,
                   client_ip: str, result: str, reason: str,
                   metadata: Optional[Dict] = None) -> AuditEvent:
        return self._write(event_type, principal, endpoint, client_ip,
                           result, reason, metadata or {})

    # ── Verification ─────────────────────────────────────────────────────────

    def verify_chain(self) -> bool:
        """Verify the hash chain of the entire log file."""
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
            # Recompute self_hash
            check_entry = {k: v for k, v in entry.items() if k != "self_hash"}
            expected    = hashlib.sha256(
                json.dumps(check_entry, sort_keys=True).encode()
            ).hexdigest()
            if entry.get("self_hash") != expected:
                return False
            prev = entry["self_hash"]
        return True

    def read_events(self) -> List[AuditEvent]:
        """Load all events from the log file."""
        events = []
        if not self._path.exists():
            return events
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    d = json.loads(line)
                    events.append(AuditEvent(**d))
                except Exception:
                    pass
        return events

    # ── Internal ──────────────────────────────────────────────────────────────

    def _write(
        self,
        event_type: str,
        principal:  str,
        endpoint:   str,
        client_ip:  str,
        result:     str,
        reason:     str,
        metadata:   Dict,
    ) -> AuditEvent:
        entry_data = {
            "event_id":   str(uuid.uuid4()),
            "ts":         datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "principal":  principal,
            "endpoint":   endpoint,
            "client_ip":  client_ip,
            "result":     result,
            "reason":     reason,
            "metadata":   metadata,
            "prev_hash":  self._prev_hash,
        }
        self_hash = hashlib.sha256(
            json.dumps(entry_data, sort_keys=True).encode()
        ).hexdigest() if self._chain else "0" * 64

        entry_data["self_hash"] = self_hash
        self._prev_hash = self_hash

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_data) + "\n")

        return AuditEvent(**entry_data)

    def _last_line(self) -> str:
        with open(self._path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return ""
            buf = b""
            pos = size - 1
            while pos >= 0:
                f.seek(pos)
                ch = f.read(1)
                if ch == b"\n" and buf:
                    break
                buf = ch + buf
                pos -= 1
        return buf.decode("utf-8", errors="ignore").strip()
