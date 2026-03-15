"""
tests/test_recovery_playbooks.py
AI Fortress · Chapter 17 · Code Sample 17.D
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from model_rollback_orchestrator import ModelRollbackOrchestrator
from data_quarantine_manager import DataQuarantineManager
from service_restoration_checker import ServiceRestorationChecker


# ── ModelRollbackOrchestrator ─────────────────────────────────────────────────

class TestModelRollbackOrchestrator:

    def _orch(self):
        orch = ModelRollbackOrchestrator()
        v1   = orch.register_version("fraud", "v1.0", b"weights-v1", blessed=True)
        v2   = orch.register_version("fraud", "v2.0", b"weights-v2", blessed=False)
        return orch, v1, v2

    def test_register_version(self):
        orch = ModelRollbackOrchestrator()
        v    = orch.register_version("model", "v1", b"weights")
        assert v.version_id
        assert v.weights_hash

    def test_rollback_blessed_version_succeeds(self):
        orch, v1, v2 = self._orch()
        result = orch.rollback(
            "INC-001", v2.version_id, v1.version_id, "ir-commander",
            checklist_overrides={
                "incident_commander_approved": True,
                "rollback_window_agreed": True,
            }
        )
        assert result.success

    def test_rollback_unblessed_fails(self):
        orch, v1, v2 = self._orch()
        result = orch.rollback(
            "INC-001", v1.version_id, v2.version_id, "ir-commander",
        )
        assert not result.success
        assert "version_is_blessed" in result.record.checklist_items

    def test_rollback_unknown_version_raises(self):
        orch = ModelRollbackOrchestrator()
        with pytest.raises(KeyError):
            orch.rollback("INC-001", "from", "ghost", "user")

    def test_rollback_history_recorded(self):
        orch, v1, v2 = self._orch()
        orch.rollback("INC-001", v2.version_id, v1.version_id, "user",
                      checklist_overrides={"incident_commander_approved": True,
                                           "rollback_window_agreed": True})
        assert len(orch.history()) == 1

    def test_persist(self, tmp_path):
        p    = tmp_path / "registry.json"
        orch = ModelRollbackOrchestrator(registry_path=p)
        orch.register_version("m", "v1", b"w")
        assert p.exists()

    def test_integrity_ok_true_when_hash_present(self):
        orch, v1, v2 = self._orch()
        result = orch.rollback("INC-001", v2.version_id, v1.version_id, "user",
                               checklist_overrides={"incident_commander_approved": True,
                                                    "rollback_window_agreed": True})
        assert result.integrity_ok


# ── DataQuarantineManager ─────────────────────────────────────────────────────

class TestDataQuarantineManager:

    def test_quarantine_dataset(self):
        mgr   = DataQuarantineManager()
        entry = mgr.quarantine("dataset-train-2026-01", "Suspected poisoning", "ciso")
        assert entry.active
        assert entry.dataset_id == "dataset-train-2026-01"

    def test_check_quarantined(self):
        mgr = DataQuarantineManager()
        mgr.quarantine("ds-001", "Poisoning", "ciso")
        result = mgr.check("ds-001")
        assert result.quarantined

    def test_check_not_quarantined(self):
        mgr    = DataQuarantineManager()
        result = mgr.check("ds-clean")
        assert not result.quarantined

    def test_clear_quarantine(self):
        mgr = DataQuarantineManager()
        mgr.quarantine("ds-001", "Poisoning", "ciso")
        mgr.clear("ds-001", "ml-ops-lead")
        assert not mgr.check("ds-001").quarantined

    def test_double_quarantine_raises(self):
        mgr = DataQuarantineManager()
        mgr.quarantine("ds-001", "reason", "ciso")
        with pytest.raises(ValueError):
            mgr.quarantine("ds-001", "reason2", "ciso")

    def test_clear_unknown_raises(self):
        mgr = DataQuarantineManager()
        with pytest.raises(KeyError):
            mgr.clear("ds-ghost", "user")

    def test_active_quarantines_list(self):
        mgr = DataQuarantineManager()
        mgr.quarantine("ds-001", "r", "ciso")
        mgr.quarantine("ds-002", "r", "ciso")
        mgr.clear("ds-001", "user")
        assert len(mgr.active_quarantines()) == 1

    def test_persist(self, tmp_path):
        p   = tmp_path / "quarantine.json"
        mgr = DataQuarantineManager(storage_path=p)
        mgr.quarantine("ds-001", "reason", "ciso")
        assert p.exists()


# ── ServiceRestorationChecker ─────────────────────────────────────────────────

def _all_pass():
    gates = [
        "model_integrity_verified", "vulnerability_patched",
        "fairness_evaluation_passed", "monitoring_alerts_configured",
        "rollback_plan_in_place", "incident_commander_approved",
        "legal_dpo_cleared", "penetration_test_passed",
    ]
    return {g: {"passed": True, "verified_by": "team", "notes": ""} for g in gates}


class TestServiceRestorationChecker:

    def test_all_pass_ready(self):
        checker = ServiceRestorationChecker()
        result  = checker.check("fraud-api", "INC-001", _all_pass())
        assert result.ready
        assert result.verdict == "READY_TO_RESTORE"

    def test_blocked_gate_not_ready(self):
        gates           = _all_pass()
        gates["vulnerability_patched"]["passed"] = False
        checker = ServiceRestorationChecker()
        result  = checker.check("fraud-api", "INC-001", gates)
        assert not result.ready
        assert "vulnerability_patched" in result.blocked_gates

    def test_no_gates_blocked(self):
        checker = ServiceRestorationChecker()
        result  = checker.check("m", "INC-001", _all_pass())
        assert len(result.blocked_gates) == 0

    def test_partial_verdict(self):
        # Only half gates passed
        gates   = {g: {"passed": False, "verified_by": "", "notes": ""}
                   for g in ["model_integrity_verified", "vulnerability_patched",
                              "fairness_evaluation_passed", "monitoring_alerts_configured"]}
        gates_all = _all_pass()
        for k in list(gates_all)[:4]:
            gates_all[k]["passed"] = False
        checker = ServiceRestorationChecker()
        result  = checker.check("m", "INC-001", gates_all)
        assert result.verdict in ("BLOCKED", "PARTIAL")

    def test_n_passed_count(self):
        checker = ServiceRestorationChecker()
        result  = checker.check("m", "INC-001", _all_pass())
        assert result.n_passed == result.n_total

    def test_custom_gates(self):
        checker = ServiceRestorationChecker(required_gates=["gate_a", "gate_b"])
        result  = checker.check("m", "INC-001", {
            "gate_a": {"passed": True, "verified_by": "u", "notes": ""},
            "gate_b": {"passed": True, "verified_by": "u", "notes": ""},
        })
        assert result.ready
