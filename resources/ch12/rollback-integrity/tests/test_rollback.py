"""
tests/test_rollback.py
AI Fortress · Chapter 12 · Code Sample 12.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from pathlib import Path

from rollback_eligibility import RollbackEligibilityChecker
from atomic_rollback import AtomicRollbackExecutor
from blast_radius_estimator import BlastRadiusEstimator, ServiceDependency
from rollback_audit_trail import RollbackAuditTrail


# ── RollbackEligibilityChecker ────────────────────────────────────────────────

class TestRollbackEligibilityChecker:

    def _checker(self):
        return RollbackEligibilityChecker(
            stage_history_fn=lambda m, v: ["dev", "staging", "production"],
            hash_lookup_fn  =lambda m, v: "abc123hash",
        )

    def test_all_checks_pass(self):
        result = self._checker().check(
            "fraud", "1.0.0", "2.0.0", target_hash="abc123hash"
        )
        assert result.eligible

    def test_same_version_fails(self):
        result = self._checker().check("fraud", "1.0.0", "1.0.0")
        assert not result.eligible
        assert "NOT_CURRENT" in result.checks_failed

    def test_quarantined_version_fails(self):
        checker = self._checker()
        checker.quarantine("fraud", "1.0.0")
        result  = checker.check("fraud", "1.0.0", "2.0.0")
        assert not result.eligible
        assert "NOT_QUARANTINED" in result.checks_failed

    def test_below_floor_fails(self):
        checker = self._checker()
        checker.set_floor("fraud", "1.5.0")
        result  = checker.check("fraud", "1.0.0", "2.0.0")
        assert not result.eligible
        assert "VERSION_FLOOR" in result.checks_failed

    def test_version_above_floor_passes(self):
        checker = self._checker()
        checker.set_floor("fraud", "1.0.0")
        result  = checker.check("fraud", "2.0.0", "3.0.0")
        assert result.eligible

    def test_hash_mismatch_fails(self):
        checker = RollbackEligibilityChecker(
            stage_history_fn=lambda m, v: ["production"],
            hash_lookup_fn  =lambda m, v: "storedHash000",
        )
        result = checker.check("fraud", "1.0.0", "2.0.0", target_hash="differentHash")
        assert not result.eligible
        assert "ARTEFACT_INTEGRITY" in result.checks_failed

    def test_no_hash_fn_skips_integrity(self):
        checker = RollbackEligibilityChecker()
        result  = checker.check("fraud", "1.0.0", "2.0.0")
        assert "ARTEFACT_INTEGRITY" in result.checks_passed

    def test_stage_not_reached_fails(self):
        checker = RollbackEligibilityChecker(
            stage_history_fn=lambda m, v: ["dev", "staging"],  # never production
        )
        result = checker.check("fraud", "1.0.0", "2.0.0", required_stage="production")
        assert "STAGE_ELIGIBILITY" in result.checks_failed

    def test_summary_string(self):
        result = self._checker().check("fraud", "1.0.0", "2.0.0", target_hash="abc123hash")
        assert "fraud@1.0.0" in result.summary()

    def test_details_populated_for_each_check(self):
        result = self._checker().check("fraud", "1.0.0", "2.0.0", target_hash="abc123hash")
        assert len(result.details) >= 5


# ── AtomicRollbackExecutor ────────────────────────────────────────────────────

class TestAtomicRollbackExecutor:

    def _executor(self, health_ok=True, swap_raises=False, audit=None):
        checker = RollbackEligibilityChecker()
        swaps   = []

        def swap_fn(m, frm, to):
            if swap_raises:
                raise RuntimeError("Swap failed")
            swaps.append((frm, to))

        health_fn = lambda m, v: health_ok
        from rollback_audit_trail import RollbackAuditTrail
        trail = RollbackAuditTrail(audit) if audit else None
        exe   = AtomicRollbackExecutor(checker, swap_fn, health_fn, audit_trail=trail)
        return exe, swaps

    def test_successful_rollback(self):
        exe, swaps = self._executor(health_ok=True)
        outcome    = exe.execute("fraud", "2.0.0", "1.0.0", "ops-team")
        assert outcome.success
        assert not outcome.reverted
        assert outcome.health_check_ok

    def test_health_check_fail_reverts(self):
        exe, swaps = self._executor(health_ok=False)
        outcome    = exe.execute("fraud", "2.0.0", "1.0.0", "ops-team")
        assert not outcome.success
        assert outcome.reverted
        # Two swaps: forward then revert
        assert len(swaps) == 2
        assert swaps[1] == ("1.0.0", "2.0.0")   # revert

    def test_swap_exception_recorded(self):
        exe, _ = self._executor(swap_raises=True)
        outcome = exe.execute("fraud", "2.0.0", "1.0.0", "ops-team")
        assert not outcome.success
        assert "exception" in outcome.reason.lower()

    def test_eligibility_failure_blocks_swap(self):
        checker = RollbackEligibilityChecker()
        checker.quarantine("fraud", "1.0.0")
        swaps   = []
        exe     = AtomicRollbackExecutor(
            checker,
            lambda m, f, t: swaps.append(t),
            lambda m, v: True,
        )
        outcome = exe.execute("fraud", "2.0.0", "1.0.0", "ops")
        assert not outcome.success
        assert len(swaps) == 0   # swap never called

    def test_audit_trail_written(self, tmp_path):
        log    = tmp_path / "rollback.jsonl"
        exe, _ = self._executor(health_ok=True, audit=log)
        exe.execute("fraud", "2.0.0", "1.0.0", "ops-team", reason="Performance regression")
        entries = json.loads(log.read_text().splitlines()[0])
        assert entries["success"] is True
        assert entries["model_name"] == "fraud"


# ── BlastRadiusEstimator ──────────────────────────────────────────────────────

class TestBlastRadiusEstimator:

    def _est(self):
        est = BlastRadiusEstimator()
        est.register_dependency("fraud-model", ServiceDependency(
            "checkout-api", "hard", "critical", owner="payments-team"))
        est.register_dependency("fraud-model", ServiceDependency(
            "analytics-service", "soft", "low", owner="data-team"))
        est.register_dependency("fraud-model", ServiceDependency(
            "audit-logger", "notify", "low"))
        return est

    def test_blast_radius_populated(self):
        report = self._est().estimate("fraud-model", "2.0.0", "1.0.0")
        assert report.total_services == 3

    def test_hard_dependencies_listed(self):
        report = self._est().estimate("fraud-model", "2.0.0", "1.0.0")
        assert len(report.hard_dependencies) == 1
        assert report.hard_dependencies[0].service_name == "checkout-api"

    def test_critical_service_blocks_proceed(self):
        report = self._est().estimate("fraud-model", "2.0.0", "1.0.0")
        assert not report.proceed_recommended
        assert "checkout-api" in report.critical_services

    def test_no_critical_hard_dep_proceed_ok(self):
        est = BlastRadiusEstimator()
        est.register_dependency("safe-model", ServiceDependency(
            "low-risk-svc", "hard", "low"))
        report = est.estimate("safe-model", "2.0.0", "1.0.0")
        assert report.proceed_recommended

    def test_no_dependencies(self):
        est    = BlastRadiusEstimator()
        report = est.estimate("no-deps-model", "2.0.0", "1.0.0")
        assert report.total_services == 0
        assert report.proceed_recommended
        assert "low-risk" in report.summary.lower()

    def test_soft_and_notify_listed(self):
        report = self._est().estimate("fraud-model", "2.0.0", "1.0.0")
        assert len(report.soft_dependencies)   == 1
        assert len(report.notify_only)         == 1

    def test_to_dict_serialisable(self):
        report = self._est().estimate("fraud-model", "2.0.0", "1.0.0")
        assert json.dumps(report.to_dict())


# ── RollbackAuditTrail ────────────────────────────────────────────────────────

class TestRollbackAuditTrail:

    def _outcome(self, success=True, reverted=False):
        from rollback_eligibility import EligibilityResult

        class FakeEligibility:
            checks_failed = []

        class FakeOutcome:
            model_name    = "fraud-model"
            from_version  = "2.0.0"
            to_version    = "1.0.0"
            success       = success
            reverted      = reverted
            executed_by   = "ops-team"
            reason        = "Test rollback"
            eligibility   = FakeEligibility()

        return FakeOutcome()

    def test_log_and_read(self, tmp_path):
        trail = RollbackAuditTrail(tmp_path / "rb.jsonl")
        trail.log(self._outcome(success=True))
        entries = trail.read_entries()
        assert len(entries) == 1
        assert entries[0].success

    def test_chain_valid(self, tmp_path):
        trail = RollbackAuditTrail(tmp_path / "rb.jsonl")
        for _ in range(4):
            trail.log(self._outcome())
        assert trail.verify_chain()

    def test_chain_invalid_after_tamper(self, tmp_path):
        path  = tmp_path / "rb.jsonl"
        trail = RollbackAuditTrail(path)
        trail.log(self._outcome())
        trail.log(self._outcome(success=False))
        lines  = path.read_text().splitlines()
        first  = json.loads(lines[0])
        first["success"] = True   # tamper
        lines[0] = json.dumps(first)
        path.write_text("\n".join(lines) + "\n")
        assert not trail.verify_chain()

    def test_reverted_flag_recorded(self, tmp_path):
        trail = RollbackAuditTrail(tmp_path / "rb.jsonl")
        trail.log(self._outcome(success=False, reverted=True))
        entries = trail.read_entries()
        assert entries[0].reverted

    def test_chain_continues_across_instances(self, tmp_path):
        path   = tmp_path / "rb.jsonl"
        trail1 = RollbackAuditTrail(path)
        trail1.log(self._outcome())
        trail2 = RollbackAuditTrail(path)
        trail2.log(self._outcome(success=False))
        assert trail2.verify_chain()
