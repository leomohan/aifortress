"""
tests/test_ir_toolkit.py
AI Fortress · Chapter 17 · Code Sample 17.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from incident_classifier import IncidentClassifier
from evidence_collector import EvidenceCollector
from timeline_builder import IncidentTimelineBuilder
from severity_escalator import SeverityEscalator


# ── IncidentClassifier ────────────────────────────────────────────────────────

class TestIncidentClassifier:

    def test_p1_on_exfiltration(self):
        clf    = IncidentClassifier()
        record = clf.classify("Data breach", ["confirmed_exfiltration"])
        assert record.severity == "P1"

    def test_p2_on_poisoning(self):
        clf    = IncidentClassifier()
        record = clf.classify("Training data issue", ["training_data_poisoned"])
        assert record.severity == "P2"

    def test_p4_on_ioc(self):
        clf    = IncidentClassifier()
        record = clf.classify("Suspicious pattern", ["indicator_of_compromise"])
        assert record.severity == "P4"

    def test_playbook_assigned(self):
        clf    = IncidentClassifier()
        record = clf.classify("Model weights", ["model_weights_replaced"])
        assert "playbook" in record.playbook

    def test_category_assigned(self):
        clf    = IncidentClassifier()
        record = clf.classify("Privacy", ["privacy_breach_confirmed"])
        assert record.category == "privacy_breach"

    def test_immediate_actions_populated(self):
        clf    = IncidentClassifier()
        record = clf.classify("Active attack", ["active_attack"])
        assert len(record.immediate_actions) > 0

    def test_notify_includes_ciso_for_p1(self):
        clf    = IncidentClassifier()
        record = clf.classify("Breach", ["confirmed_exfiltration"])
        assert "ciso" in record.notify

    def test_fairness_incident_notifies_ethics(self):
        clf    = IncidentClassifier()
        record = clf.classify("Bias", ["fairness_violation_confirmed"])
        assert "ai-ethics-lead" in record.notify

    def test_empty_indicators_raise(self):
        clf = IncidentClassifier()
        with pytest.raises(ValueError):
            clf.classify("Bad", [])

    def test_incident_id_unique(self):
        clf = IncidentClassifier()
        r1  = clf.classify("A", ["near_miss"])
        r2  = clf.classify("B", ["near_miss"])
        assert r1.incident_id != r2.incident_id

    def test_dpo_notified_on_privacy_p1(self):
        clf    = IncidentClassifier()
        record = clf.classify("Exfil", ["confirmed_exfiltration", "privacy_breach_confirmed"])
        assert "dpo" in record.notify

    def test_custom_score_override(self):
        clf    = IncidentClassifier(custom_scores={"my_custom_indicator": 10})
        record = clf.classify("Custom", ["my_custom_indicator"])
        assert record.severity == "P1"


# ── EvidenceCollector ─────────────────────────────────────────────────────────

class TestEvidenceCollector:

    def test_collect_returns_item(self):
        ec   = EvidenceCollector("INC-001")
        item = ec.collect(b"model weights bytes", "model_artefact", "Snapshot of weights")
        assert item.content_hash
        assert item.chain_hash
        assert item.size_bytes == len(b"model weights bytes")

    def test_chain_valid_on_multiple_items(self):
        ec = EvidenceCollector("INC-001")
        ec.collect(b"first",  "system_log", "First log")
        ec.collect(b"second", "api_log",    "Second log")
        ec.collect(b"third",  "inference_log", "Inference data")
        chain = ec.verify_chain()
        assert chain.chain_valid
        assert chain.item_count == 3

    def test_tampered_chain_detected(self):
        ec = EvidenceCollector("INC-001")
        ec.collect(b"data", "system_log", "Log")
        # Tamper chain hash of first item
        ec._items[0].chain_hash = "a" * 64
        chain = ec.verify_chain()
        assert not chain.chain_valid

    def test_seal_item(self):
        ec   = EvidenceCollector("INC-001")
        item = ec.collect(b"evidence", "configuration", "Config file")
        ec.seal(item.evidence_id)
        assert item.sealed

    def test_seal_unknown_raises(self):
        ec = EvidenceCollector("INC-001")
        with pytest.raises(KeyError):
            ec.seal("nonexistent")

    def test_manifest_written(self, tmp_path):
        p  = tmp_path / "manifest.json"
        ec = EvidenceCollector("INC-001", storage_path=p)
        ec.collect(b"data", "system_log", "Log")
        assert p.exists()
        items = json.loads(p.read_text())
        assert len(items) == 1

    def test_hash_deterministic(self):
        import hashlib
        ec   = EvidenceCollector("INC-001")
        data = b"test evidence"
        item = ec.collect(data, "system_log", "desc")
        assert item.content_hash == hashlib.sha256(data).hexdigest()


# ── IncidentTimelineBuilder ───────────────────────────────────────────────────

class TestIncidentTimelineBuilder:

    def test_build_timeline(self):
        tb = IncidentTimelineBuilder("INC-001")
        tb.add_event("incident_start",  "Attack began",       "attacker")
        tb.add_event("detection",       "Anomaly detected",   "siem")
        tb.add_event("containment",     "Model suspended",    "ir-team")
        tb.add_event("recovery",        "Model restored",     "ml-ops")
        tl = tb.build()
        assert len(tl.events) == 4

    def test_ttd_computed(self):
        tb = IncidentTimelineBuilder("INC-001")
        tb.add_event("incident_start", "Start", "sys",
                     timestamp="2026-01-01T10:00:00+00:00")
        tb.add_event("detection",      "Found", "siem",
                     timestamp="2026-01-01T10:30:00+00:00")
        tl = tb.build()
        assert tl.ttd_minutes == 30.0

    def test_ttc_computed(self):
        tb = IncidentTimelineBuilder("INC-001")
        tb.add_event("detection",   "Found",     "siem",
                     timestamp="2026-01-01T10:00:00+00:00")
        tb.add_event("containment", "Contained", "ir",
                     timestamp="2026-01-01T12:00:00+00:00")
        tl = tb.build()
        assert tl.ttc_minutes == 120.0

    def test_missing_milestones_return_none(self):
        tb = IncidentTimelineBuilder("INC-001")
        tb.add_event("detection", "Found", "siem")
        tl = tb.build()
        assert tl.ttd_minutes is None    # no incident_start
        assert tl.ttc_minutes is None    # no containment

    def test_milestones_flagged(self):
        tb = IncidentTimelineBuilder("INC-001")
        tb.add_event("detection",  "Found", "siem")
        tb.add_event("analyst_note", "Looked at logs", "analyst")
        tl = tb.build()
        ms = [e for e in tl.events if e.milestone]
        assert len(ms) == 1

    def test_save_json(self, tmp_path):
        tb = IncidentTimelineBuilder("INC-001")
        tb.add_event("detection", "Found", "siem")
        tl = tb.build()
        p  = tmp_path / "timeline.json"
        tl.save_json(p)
        data = json.loads(p.read_text())
        assert "events" in data


# ── SeverityEscalator ─────────────────────────────────────────────────────────

class TestSeverityEscalator:

    def test_no_escalation_without_trigger(self):
        esc    = SeverityEscalator("INC-001", "P3")
        result = esc.evaluate()
        assert result.current_severity == "P3"
        assert not result.escalated

    def test_exfiltration_escalates_to_p1(self):
        esc    = SeverityEscalator("INC-001", "P3")
        result = esc.evaluate(exfiltration=True)
        assert result.current_severity == "P1"
        assert result.escalated

    def test_privacy_impact_escalates_to_p2(self):
        esc    = SeverityEscalator("INC-001", "P4")
        result = esc.evaluate(privacy_impact=True)
        assert result.current_severity == "P2"

    def test_large_population_p1(self):
        esc    = SeverityEscalator("INC-001", "P3")
        result = esc.evaluate(affected_individuals=50_000)
        assert result.current_severity == "P1"

    def test_severity_never_decreases(self):
        esc = SeverityEscalator("INC-001", "P1")
        result = esc.evaluate()   # no triggers
        assert result.current_severity == "P1"

    def test_escalation_history_recorded(self):
        esc = SeverityEscalator("INC-001", "P4")
        esc.evaluate(privacy_impact=True)
        esc.evaluate(exfiltration=True)
        assert len(esc._history) == 2

    def test_force_escalate(self):
        esc = SeverityEscalator("INC-001", "P3")
        esc.force_escalate("P1", "ciso", "Manual override — active attack confirmed")
        assert esc.current_severity == "P1"

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError):
            SeverityEscalator("INC-001", "P9")
