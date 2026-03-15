"""
blast_radius_estimator.py  —  Downstream service impact analysis for rollbacks
AI Fortress · Chapter 12 · Code Sample 12.C

Estimates the downstream blast radius of rolling back a model by querying
a service dependency map. Helps operators understand which services need
coordination before proceeding.

Dependency types:
  hard   — service will fail without the model (synchronous inference)
  soft   — service degrades gracefully (async, cached, fallback available)
  notify — service should be informed but is not impacted directly
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ServiceDependency:
    service_name: str
    dep_type:     str    # "hard" | "soft" | "notify"
    risk_tier:    str    # "critical" | "high" | "low"
    owner:        str = ""
    notes:        str = ""


@dataclass
class BlastRadiusReport:
    model_name:         str
    from_version:       str
    to_version:         str
    total_services:     int
    hard_dependencies:  List[ServiceDependency]
    soft_dependencies:  List[ServiceDependency]
    notify_only:        List[ServiceDependency]
    critical_services:  List[str]       # service names rated critical
    proceed_recommended: bool           # False if any hard critical dep exists
    summary:            str

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


class BlastRadiusEstimator:
    """
    Estimates downstream impact of a model rollback.

    Parameters
    ----------
    dependency_map : Dict of model_name → List[ServiceDependency].
                     Represents which services depend on which models.
    """

    def __init__(self, dependency_map: Optional[Dict[str, List[ServiceDependency]]] = None):
        self._deps = dependency_map or {}

    def register_dependency(
        self,
        model_name:   str,
        service:      ServiceDependency,
    ) -> None:
        self._deps.setdefault(model_name, []).append(service)

    def estimate(
        self,
        model_name:   str,
        from_version: str,
        to_version:   str,
    ) -> BlastRadiusReport:
        deps = self._deps.get(model_name, [])

        hard     = [d for d in deps if d.dep_type == "hard"]
        soft     = [d for d in deps if d.dep_type == "soft"]
        notify   = [d for d in deps if d.dep_type == "notify"]
        critical = [d.service_name for d in deps if d.risk_tier == "critical"]

        proceed  = len([d for d in hard if d.risk_tier == "critical"]) == 0

        if not deps:
            summary = f"No registered dependencies for {model_name}. Rollback is low-risk."
        else:
            parts = []
            if hard:
                parts.append(f"{len(hard)} hard dependenc{'y' if len(hard)==1 else 'ies'}")
            if critical:
                parts.append(f"{len(critical)} critical service(s): {', '.join(critical)}")
            summary = (
                f"Rollback {model_name} {from_version}→{to_version}: "
                f"{', '.join(parts)}. "
                + ("⚠️ Coordinate with critical services before proceeding."
                   if not proceed else "✅ Proceed with standard notification.")
            )

        return BlastRadiusReport(
            model_name          = model_name,
            from_version        = from_version,
            to_version          = to_version,
            total_services      = len(deps),
            hard_dependencies   = hard,
            soft_dependencies   = soft,
            notify_only         = notify,
            critical_services   = critical,
            proceed_recommended = proceed,
            summary             = summary,
        )


# ─────────────────────────────────────────────────────────────────────────────

"""
rollback_audit_trail.py  —  Tamper-evident rollback audit log
AI Fortress · Chapter 12 · Code Sample 12.C

SHA-256 hash-chained JSON Lines log for all rollback attempts.
"""
import hashlib as _hashlib
import json as _json
import uuid as _uuid
from dataclasses import dataclass as _dataclass, field as _field
from datetime import datetime as _datetime, timezone as _timezone
from pathlib import Path as _Path
from typing import List as _List, Optional as _Optional


@_dataclass
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
    checks_failed:  _List[str]
    prev_hash:      str
    self_hash:      str


class RollbackAuditTrail:
    """Tamper-evident rollback audit trail using SHA-256 hash chaining."""

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

    def log(self, outcome: "RollbackOutcome") -> RollbackAuditEntry:  # noqa: F821
        data = {
            "entry_id":      str(_uuid.uuid4()),
            "ts":            _datetime.now(_timezone.utc).isoformat(),
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
        self_hash = _hashlib.sha256(
            _json.dumps(data, sort_keys=True).encode()
        ).hexdigest()
        data["self_hash"] = self_hash
        self._prev_hash   = self_hash

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(_json.dumps(data) + "\n")

        return RollbackAuditEntry(**data)

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
            check    = {k: v for k, v in entry.items() if k != "self_hash"}
            expected = _hashlib.sha256(
                _json.dumps(check, sort_keys=True).encode()
            ).hexdigest()
            if entry.get("self_hash") != expected:
                return False
            prev = entry["self_hash"]
        return True

    def read_entries(self) -> _List[RollbackAuditEntry]:
        if not self._path.exists():
            return []
        entries = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    entries.append(RollbackAuditEntry(**_json.loads(line)))
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
