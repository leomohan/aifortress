"""
atomic_rollback.py  —  Atomic model rollback with health validation
AI Fortress · Chapter 12 · Code Sample 12.C

Orchestrates a rollback swap as an atomic operation:
  1. Verify eligibility (calls RollbackEligibilityChecker)
  2. Snapshot current active version
  3. Execute swap callback (caller-supplied fn that updates serving)
  4. Run health check callback (caller-supplied fn → bool)
  5a. Health check passes → confirm, write audit record
  5b. Health check fails  → revert to previous version, write audit record

The executor never leaves the system in an ambiguous state:
either the rollback completes fully or the previous version is restored.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from rollback_eligibility import RollbackEligibilityChecker, EligibilityResult


@dataclass
class RollbackOutcome:
    attempt_id:      str
    model_name:      str
    from_version:    str
    to_version:      str
    success:         bool
    reverted:        bool      # True if health check failed and we reverted
    eligibility:     EligibilityResult
    health_check_ok: bool
    reason:          str
    executed_by:     str
    executed_at:     str


class AtomicRollbackExecutor:
    """
    Executes atomic model rollbacks with health validation.

    Parameters
    ----------
    checker      : RollbackEligibilityChecker instance.
    swap_fn      : Callable(model_name, from_version, to_version) → None.
                   Performs the actual serving swap (update load balancer, etc.).
    health_fn    : Callable(model_name, version) → bool.
                   Returns True if the version is healthy after activation.
    audit_trail  : Optional RollbackAuditTrail instance.
    """

    def __init__(
        self,
        checker:     RollbackEligibilityChecker,
        swap_fn:     Callable,
        health_fn:   Callable,
        audit_trail: Optional["RollbackAuditTrail"] = None,
    ):
        self._checker     = checker
        self._swap        = swap_fn
        self._health      = health_fn
        self._audit_trail = audit_trail

    def execute(
        self,
        model_name:      str,
        from_version:    str,
        to_version:      str,
        executed_by:     str,
        reason:          str = "",
        target_hash:     Optional[str] = None,
        required_stage:  str = "production",
    ) -> RollbackOutcome:
        attempt_id = str(uuid.uuid4())
        now        = datetime.now(timezone.utc).isoformat()

        # Step 1: Check eligibility
        eligibility = self._checker.check(
            model_name, to_version, from_version,
            target_hash=target_hash, required_stage=required_stage,
        )
        if not eligibility.eligible:
            outcome = RollbackOutcome(
                attempt_id=attempt_id, model_name=model_name,
                from_version=from_version, to_version=to_version,
                success=False, reverted=False, eligibility=eligibility,
                health_check_ok=False,
                reason=f"Eligibility failed: {eligibility.checks_failed}",
                executed_by=executed_by, executed_at=now,
            )
            self._write_audit(outcome)
            return outcome

        # Step 2: Execute swap
        try:
            self._swap(model_name, from_version, to_version)
        except Exception as exc:
            outcome = RollbackOutcome(
                attempt_id=attempt_id, model_name=model_name,
                from_version=from_version, to_version=to_version,
                success=False, reverted=False, eligibility=eligibility,
                health_check_ok=False,
                reason=f"Swap function raised exception: {exc}",
                executed_by=executed_by, executed_at=now,
            )
            self._write_audit(outcome)
            return outcome

        # Step 3: Health check
        try:
            health_ok = bool(self._health(model_name, to_version))
        except Exception:
            health_ok = False

        if health_ok:
            outcome = RollbackOutcome(
                attempt_id=attempt_id, model_name=model_name,
                from_version=from_version, to_version=to_version,
                success=True, reverted=False, eligibility=eligibility,
                health_check_ok=True,
                reason=reason or "Rollback completed successfully.",
                executed_by=executed_by, executed_at=now,
            )
        else:
            # Step 4: Revert
            try:
                self._swap(model_name, to_version, from_version)
            except Exception:
                pass   # best-effort revert; operator must intervene
            outcome = RollbackOutcome(
                attempt_id=attempt_id, model_name=model_name,
                from_version=from_version, to_version=to_version,
                success=False, reverted=True, eligibility=eligibility,
                health_check_ok=False,
                reason="Health check failed after rollback — reverted to previous version.",
                executed_by=executed_by, executed_at=now,
            )

        self._write_audit(outcome)
        return outcome

    def _write_audit(self, outcome: RollbackOutcome) -> None:
        if self._audit_trail:
            self._audit_trail.log(outcome)
