"""
promotion_gate.py  —  Stage promotion approval gate for ML model versions
AI Fortress · Chapter 12 · Code Sample 12.A

Enforces a sequential promotion workflow before a model version can
advance to production:

  dev  →  staging  →  production

Each transition requires a gate decision. Gates may be:
  - Auto-approved by a rule (e.g. CI passed all checks)
  - Manually approved by a named approver

Blocked transitions are recorded with a reason. A version cannot
skip stages (dev → production directly is rejected).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


_STAGES     = ["dev", "staging", "production"]
_STAGE_IDX  = {s: i for i, s in enumerate(_STAGES)}
_TRANSITIONS: Dict[str, str] = {
    "dev":     "staging",
    "staging": "production",
}


@dataclass
class PromotionRecord:
    record_id:    str
    model_name:   str
    version:      str
    from_stage:   str
    to_stage:     str
    decision:     str        # "approved" | "blocked"
    decided_by:   str
    decided_at:   str
    reason:       str = ""


@dataclass
class PromotionStatus:
    model_name:  str
    version:     str
    stage:       str         # current stage
    history:     List[PromotionRecord]

    @property
    def is_production(self) -> bool:
        return self.stage == "production"


class PromotionGate:
    """
    Manages stage-by-stage model promotion with approval enforcement.

    Parameters
    ----------
    auto_approve_fn : Optional callable(model_name, version, to_stage) → bool.
                      If returns True, the promotion is auto-approved.
    audit_path      : Optional JSON Lines path.
    """

    def __init__(
        self,
        auto_approve_fn: Optional[Callable] = None,
        audit_path:      Optional[str | Path] = None,
    ):
        # (model_name, version) → PromotionStatus
        self._statuses: Dict[Tuple[str, str], PromotionStatus] = {}
        self._auto_fn   = auto_approve_fn
        self._audit     = Path(audit_path) if audit_path else None

    def register_version(
        self, model_name: str, version: str
    ) -> PromotionStatus:
        """Register a new version at the 'dev' stage."""
        key = (model_name, version)
        if key in self._statuses:
            return self._statuses[key]
        status = PromotionStatus(
            model_name=model_name, version=version,
            stage="dev", history=[],
        )
        self._statuses[key] = status
        self._log("version_registered_at_dev", model=model_name, version=version)
        return status

    def promote(
        self,
        model_name: str,
        version:    str,
        approver:   str,
        reason:     str = "",
    ) -> PromotionRecord:
        """
        Attempt to promote a version to the next stage.
        Raises ValueError if already at production, or if auto_approve_fn blocks it.
        """
        status   = self._get_status(model_name, version)
        current  = status.stage
        next_stage = _TRANSITIONS.get(current)

        if next_stage is None:
            raise ValueError(
                f"Model '{model_name}@{version}' is already at '{current}'. "
                "No further promotion is possible."
            )

        # Check auto-approval rule
        if self._auto_fn:
            allowed = self._auto_fn(model_name, version, next_stage)
        else:
            allowed = True   # manual approval assumed if no rule

        decision = "approved" if allowed else "blocked"
        record   = PromotionRecord(
            record_id  = str(uuid.uuid4()),
            model_name = model_name,
            version    = version,
            from_stage = current,
            to_stage   = next_stage,
            decision   = decision,
            decided_by = approver,
            decided_at = datetime.now(timezone.utc).isoformat(),
            reason     = reason,
        )
        status.history.append(record)

        if allowed:
            status.stage = next_stage

        self._log("promotion_" + decision, model=model_name, version=version,
                  from_stage=current, to_stage=next_stage, approver=approver,
                  reason=reason)
        return record

    def block(
        self,
        model_name: str,
        version:    str,
        blocked_by: str,
        reason:     str,
    ) -> PromotionRecord:
        """Explicitly block a version from further promotion."""
        status    = self._get_status(model_name, version)
        next_stage = _TRANSITIONS.get(status.stage, "production")
        record    = PromotionRecord(
            record_id  = str(uuid.uuid4()),
            model_name = model_name,
            version    = version,
            from_stage = status.stage,
            to_stage   = next_stage,
            decision   = "blocked",
            decided_by = blocked_by,
            decided_at = datetime.now(timezone.utc).isoformat(),
            reason     = reason,
        )
        status.history.append(record)
        self._log("promotion_blocked", model=model_name, version=version,
                  reason=reason, blocked_by=blocked_by)
        return record

    def get_status(self, model_name: str, version: str) -> PromotionStatus:
        return self._get_status(model_name, version)

    def versions_at_stage(self, stage: str) -> List[Tuple[str, str]]:
        return [
            (s.model_name, s.version)
            for s in self._statuses.values()
            if s.stage == stage
        ]

    def _get_status(self, model_name: str, version: str) -> PromotionStatus:
        key = (model_name, version)
        if key not in self._statuses:
            raise KeyError(
                f"Version '{model_name}@{version}' not registered. "
                "Call register_version() first."
            )
        return self._statuses[key]

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
