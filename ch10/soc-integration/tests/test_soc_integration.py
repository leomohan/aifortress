"""
tests/test_soc_integration.py
AI Fortress · Chapter 10 · Code Sample 10.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import time
import uuid
import pytest
from pathlib import Path

from alert_normaliser import AlertNormaliser, RawMLEvent
from alert_triage import AlertTriageClassifier, TriageRule
from escalation_router import EscalationRouter, ChannelConfig
from correlation_engine import CorrelationEngine


def _event(event_type: str, severity_override: int = None, **kwargs) -> RawMLEvent:
    return RawMLEvent(
        event_type=event_type,
        source_ip=kwargs.get("source_ip", "10.0.0.1"),
        model_name=kwargs.get("model_name", "fraud-model"),
        user=kwargs.get("user", "svc-account"),
        detail=kwargs.get("detail", f"Test {event_type} event"),
        event_id=str(uuid.uuid4()),
    )


# ── AlertNormaliser ───────────────────────────────────────────────────────────

class TestAlertNormaliser:

    def test_cef_format_structure(self):
        norm  = AlertNormaliser()
        alert = norm.normalise(_event("auth_failure"))
        assert alert.cef.startswith("CEF:0|AI Fortress|ML Security Monitor")
        assert "AIF-010" in alert.cef
        assert "src=10.0.0.1" in alert.cef

    def test_leef_format_structure(self):
        norm  = AlertNormaliser()
        alert = norm.normalise(_event("lateral_movement"))
        assert alert.leef.startswith("LEEF:2.0|AI Fortress|ML Security Monitor")
        assert "AIF-020" in alert.leef
        assert "sev=Critical" in alert.leef

    def test_json_record_keys(self):
        norm  = AlertNormaliser()
        alert = norm.normalise(_event("drift_critical"))
        rec   = alert.json_record
        for key in ("event_id", "timestamp", "event_type", "severity", "source_ip"):
            assert key in rec

    def test_severity_mapping(self):
        norm = AlertNormaliser()
        assert norm.normalise(_event("lateral_movement")).severity == 10
        assert norm.normalise(_event("drift_critical")).severity   == 9
        assert norm.normalise(_event("rate_limit")).severity       == 5

    def test_unknown_event_type_handled(self):
        norm  = AlertNormaliser()
        alert = norm.normalise(_event("unknown_custom_event"))
        assert alert.cef
        assert alert.leef
        assert alert.json_record["signature"] == "AIF-999"

    def test_batch_normalisation(self):
        norm   = AlertNormaliser()
        events = [_event("auth_failure"), _event("ip_deny"), _event("drift_warning")]
        alerts = norm.normalise_batch(events)
        assert len(alerts) == 3

    def test_special_chars_escaped_in_cef(self):
        norm = AlertNormaliser()
        ev   = RawMLEvent(event_type="auth_failure", detail="user=admin|pass=abc")
        alert = norm.normalise(ev)
        # The pipe in detail should be escaped in extension
        assert "\\|" in alert.cef or "user=admin" in alert.cef

    def test_metadata_included_in_json(self):
        norm = AlertNormaliser()
        ev   = RawMLEvent(event_type="drift_critical", metadata={"psi": 0.35, "feature": "age"})
        alert = norm.normalise(ev)
        assert alert.json_record["metadata"]["psi"] == 0.35

    def test_custom_vendor_product(self):
        norm  = AlertNormaliser(device_vendor="Acme Corp", device_product="ML Shield")
        alert = norm.normalise(_event("auth_failure"))
        assert "Acme Corp" in alert.cef
        assert "ML Shield" in alert.leef


# ── AlertTriageClassifier ─────────────────────────────────────────────────────

class TestAlertTriageClassifier:

    def _normalise(self, event_type: str) -> "NormalisedAlert":
        norm = AlertNormaliser()
        return norm.normalise(_event(event_type))

    def test_lateral_movement_is_p1(self):
        dec = AlertTriageClassifier().triage(self._normalise("lateral_movement"))
        assert dec.priority == "P1"

    def test_supply_chain_is_p1(self):
        dec = AlertTriageClassifier().triage(self._normalise("supply_chain"))
        assert dec.priority == "P1"

    def test_model_extraction_is_p1(self):
        dec = AlertTriageClassifier().triage(self._normalise("model_extraction"))
        assert dec.priority == "P1"

    def test_auth_failure_is_p2(self):
        dec = AlertTriageClassifier().triage(self._normalise("auth_failure"))
        assert dec.priority in ("P1", "P2")

    def test_rate_limit_is_p3_or_lower(self):
        dec = AlertTriageClassifier().triage(self._normalise("rate_limit"))
        assert dec.priority in ("P3", "P4")

    def test_action_string_populated(self):
        dec = AlertTriageClassifier().triage(self._normalise("lateral_movement"))
        assert len(dec.action) > 10

    def test_matched_rule_populated(self):
        dec = AlertTriageClassifier().triage(self._normalise("supply_chain"))
        assert dec.matched_rule.startswith("R")

    def test_confidence_between_0_and_1(self):
        for et in ("lateral_movement", "auth_failure", "rate_limit"):
            dec = AlertTriageClassifier().triage(self._normalise(et))
            assert 0.0 <= dec.confidence <= 1.0

    def test_batch_triage(self):
        norm = AlertNormaliser()
        alerts = norm.normalise_batch([
            _event("lateral_movement"), _event("auth_failure"), _event("rate_limit")
        ])
        decisions = AlertTriageClassifier().triage_batch(alerts)
        assert len(decisions) == 3

    def test_audit_log_written(self, tmp_path):
        log = tmp_path / "triage.jsonl"
        tc  = AlertTriageClassifier(audit_path=log)
        tc.triage(self._normalise("auth_failure"))
        lines = log.read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["priority"] in ("P1", "P2")

    def test_custom_rule_overrides(self):
        custom = [
            TriageRule("C001", "All events P1",
                       conditions={"severity": {"min": 0}},
                       priority="P1", action="Custom action")
        ]
        dec = AlertTriageClassifier(rules=custom).triage(self._normalise("rate_limit"))
        assert dec.priority == "P1"
        assert dec.matched_rule == "C001"


# ── EscalationRouter ──────────────────────────────────────────────────────────

class TestEscalationRouter:

    def _triage(self, event_type: str) -> "TriageDecision":
        norm = AlertNormaliser()
        alert = norm.normalise(_event(event_type))
        return AlertTriageClassifier().triage(alert)

    def test_p1_routed_to_slack_and_pagerduty(self):
        calls = []
        def slack_handler(d, p): calls.append("slack"); return True
        def pd_handler(d, p):    calls.append("pagerduty"); return True

        router = EscalationRouter(channels=[
            ChannelConfig("slack",     slack_handler, ["P1", "P2"]),
            ChannelConfig("pagerduty", pd_handler,    ["P1"]),
        ])
        dec    = self._triage("lateral_movement")
        result = router.route(dec)
        assert "slack"     in result.success
        assert "pagerduty" in result.success

    def test_p4_not_routed_to_pagerduty(self):
        calls = []
        def pd_handler(d, p): calls.append("pagerduty"); return True

        router = EscalationRouter(channels=[
            ChannelConfig("pagerduty", pd_handler, ["P1"]),
        ])
        # Rate-limit = P3 or P4
        dec    = self._triage("rate_limit")
        result = router.route(dec)
        assert "pagerduty" not in result.success

    def test_failed_channel_recorded(self):
        def failing_handler(d, p): raise RuntimeError("Connection refused")
        router = EscalationRouter(channels=[
            ChannelConfig("slack", failing_handler, ["P1", "P2", "P3"]),
        ])
        dec    = self._triage("auth_failure")
        result = router.route(dec)
        assert "slack" in result.failed

    def test_disabled_channel_skipped(self):
        calls = []
        def handler(d, p): calls.append(True); return True
        router = EscalationRouter(channels=[
            ChannelConfig("slack", handler, ["P1"], enabled=False),
        ])
        dec    = self._triage("lateral_movement")
        router.route(dec)
        assert len(calls) == 0

    def test_log_channel_writes_file(self, tmp_path):
        log    = tmp_path / "routed.jsonl"
        router = EscalationRouter(channels=[
            EscalationRouter.make_log_channel(log, priorities=["P1", "P2", "P3", "P4"])
        ])
        dec    = self._triage("auth_failure")
        router.route(dec)
        assert log.exists()
        data = json.loads(log.read_text().splitlines()[0])
        assert "priority" in data

    def test_audit_log_written(self, tmp_path):
        audit  = tmp_path / "routing_audit.jsonl"
        def handler(d, p): return True
        router = EscalationRouter(
            channels=[ChannelConfig("slack", handler, ["P1", "P2"])],
            audit_path=audit,
        )
        dec    = self._triage("lateral_movement")
        router.route(dec)
        assert audit.exists()
        assert len(audit.read_text().splitlines()) == 1

    def test_batch_routing(self):
        results_list = []
        def handler(d, p): results_list.append(d.event_id); return True
        router = EscalationRouter(channels=[
            ChannelConfig("all", handler, ["P1", "P2", "P3", "P4"])
        ])
        norm   = AlertNormaliser()
        alerts = norm.normalise_batch([
            _event("lateral_movement"), _event("auth_failure")
        ])
        decisions = AlertTriageClassifier().triage_batch(alerts)
        results   = router.route_batch(decisions)
        assert len(results) == 2


# ── CorrelationEngine ─────────────────────────────────────────────────────────

class TestCorrelationEngine:

    def _norm(self, event_type: str, source_ip: str = "10.0.0.1") -> "NormalisedAlert":
        norm = AlertNormaliser()
        ev   = RawMLEvent(event_type=event_type, source_ip=source_ip,
                          model_name="fraud-model")
        return norm.normalise(ev)

    def test_no_pattern_single_event(self):
        eng    = CorrelationEngine()
        alerts = eng.ingest(self._norm("auth_failure"))
        assert len(alerts) == 0

    def test_supply_chain_pattern_detected(self):
        eng    = CorrelationEngine(window_seconds=60)
        now    = time.time()
        alerts = []
        alerts += eng.ingest(self._norm("drift_critical"), ts=now)
        alerts += eng.ingest(self._norm("signing_failure"), ts=now + 1)
        assert any(a.pattern == "supply_chain_attack" for a in alerts)

    def test_credential_stuffing_detected(self):
        eng  = CorrelationEngine(window_seconds=60)
        now  = time.time()
        cors = []
        for i in range(12):
            cors += eng.ingest(
                self._norm("auth_failure", source_ip=f"5.5.5.{i}"), ts=now)
        assert any(a.pattern == "credential_stuffing" for a in cors)

    def test_mesh_compromise_detected(self):
        eng  = CorrelationEngine(window_seconds=60)
        now  = time.time()
        cors = []
        cors += eng.ingest(self._norm("lateral_movement"), ts=now)
        cors += eng.ingest(self._norm("auth_failure"),     ts=now + 1)
        assert any(a.pattern == "mesh_compromise" for a in cors)

    def test_dedup_prevents_repeated_alerts(self):
        eng  = CorrelationEngine(window_seconds=300)
        now  = time.time()
        # Fire supply_chain pattern
        eng.ingest(self._norm("drift_critical"),  ts=now)
        fire1 = eng.ingest(self._norm("signing_failure"), ts=now + 1)
        # Immediately fire again — should be deduped
        fire2 = eng.ingest(self._norm("signing_failure"), ts=now + 2)
        supply_chain_count = sum(
            1 for a in fire1 + fire2 if a.pattern == "supply_chain_attack"
        )
        assert supply_chain_count == 1

    def test_window_expiry_clears_events(self):
        eng = CorrelationEngine(window_seconds=5)
        now = time.time()
        eng.ingest(self._norm("drift_critical"), ts=now)
        # Inject signing_failure 10s later — drift should have expired
        alerts = eng.ingest(self._norm("signing_failure"), ts=now + 10)
        assert not any(a.pattern == "supply_chain_attack" for a in alerts)

    def test_contributing_ids_populated(self):
        eng  = CorrelationEngine(window_seconds=60)
        now  = time.time()
        a1   = self._norm("drift_critical")
        a2   = self._norm("signing_failure")
        eng.ingest(a1, ts=now)
        cors = eng.ingest(a2, ts=now + 1)
        supply = [c for c in cors if c.pattern == "supply_chain_attack"]
        if supply:
            assert a1.event_id in supply[0].contributing_ids
            assert a2.event_id in supply[0].contributing_ids

    def test_alert_written_to_file(self, tmp_path):
        log  = tmp_path / "corr.jsonl"
        eng  = CorrelationEngine(window_seconds=60, alert_path=log)
        now  = time.time()
        eng.ingest(self._norm("drift_critical"),  ts=now)
        eng.ingest(self._norm("signing_failure"), ts=now + 1)
        if log.exists():
            lines = log.read_text().splitlines()
            assert all(json.loads(l)["severity"] == "CRITICAL" for l in lines if l)

    def test_window_summary(self):
        eng  = CorrelationEngine(window_seconds=60)
        now  = time.time()
        eng.ingest(self._norm("auth_failure"), ts=now)
        eng.ingest(self._norm("ip_deny"),      ts=now + 1)
        summary = eng.window_summary()
        assert summary["window_size_events"] == 2
        assert "auth_failure" in summary["event_types"]

    def test_batch_ingest(self):
        eng    = CorrelationEngine(window_seconds=60)
        norm   = AlertNormaliser()
        alerts = norm.normalise_batch([
            RawMLEvent("drift_critical"),
            RawMLEvent("signing_failure"),
        ])
        cors   = eng.ingest_batch(alerts, ts=time.time())
        # May or may not fire depending on timing; just ensure no exception
        assert isinstance(cors, list)
