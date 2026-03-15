"""
tests/test_access_review.py
AI Fortress · Chapter 11 · Code Sample 11.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from stale_entitlement_detector import StaleEntitlementDetector, EntitlementRecord
from peer_group_anomaly import PeerGroupAnomalyDetector, PeerGroupMember
from review_workflow import ReviewWorkflowEngine
from access_certification_report import AccessCertificationReporter


# ── StaleEntitlementDetector ──────────────────────────────────────────────────

class TestStaleEntitlementDetector:

    def _now(self):
        return datetime.now(timezone.utc)

    def _ago(self, days):
        return (self._now() - timedelta(days=days)).isoformat()

    def test_active_entitlement_retain(self):
        det = StaleEntitlementDetector(lookback_days=90)
        rec = EntitlementRecord(
            principal="alice", permissions={"model:read"},
            last_used_at=self._ago(10), granted_at=self._ago(200)
        )
        report = det.scan([rec])
        assert report.findings[0].recommendation == "RETAIN"

    def test_stale_low_priv_review(self):
        det = StaleEntitlementDetector(lookback_days=90)
        rec = EntitlementRecord(
            principal="bob", permissions={"model:read", "training:read"},
            last_used_at=self._ago(120), granted_at=self._ago(300)
        )
        report = det.scan([rec])
        f = report.findings[0]
        assert f.status == "STALE"
        assert f.recommendation == "REVIEW"

    def test_stale_high_priv_revoke(self):
        det = StaleEntitlementDetector(lookback_days=90)
        rec = EntitlementRecord(
            principal="carol", permissions={"model:deploy", "secrets:read"},
            last_used_at=self._ago(120), granted_at=self._ago(300)
        )
        report = det.scan([rec])
        f = report.findings[0]
        assert f.status  == "STALE"
        assert f.risk    == "RISKY"
        assert f.recommendation == "REVOKE"

    def test_dormant_account_revoke(self):
        det = StaleEntitlementDetector(lookback_days=90)
        rec = EntitlementRecord(
            principal="svc-old", permissions={"data:write"},
            last_used_at="", granted_at=self._ago(200),
            account_type="service"
        )
        report = det.scan([rec])
        f = report.findings[0]
        assert f.status == "DORMANT"
        assert f.recommendation == "REVOKE"

    def test_summary_counts(self):
        det  = StaleEntitlementDetector(lookback_days=90)
        recs = [
            EntitlementRecord("a", {"model:read"}, self._ago(10),  self._ago(100)),
            EntitlementRecord("b", {"model:read"}, self._ago(120), self._ago(200)),
            EntitlementRecord("c", {"model:deploy"}, self._ago(120), self._ago(200)),
            EntitlementRecord("d", {"model:read"}, "", self._ago(200)),
        ]
        report = det.scan(recs)
        assert report.total   == 4
        assert report.active  == 1
        assert report.stale   == 2
        assert report.dormant == 1

    def test_high_priv_perms_listed(self):
        det = StaleEntitlementDetector()
        rec = EntitlementRecord(
            "dave", {"model:deploy", "secrets:read", "model:read"},
            self._ago(100), self._ago(200)
        )
        report = det.scan([rec])
        f = report.findings[0]
        assert "model:deploy" in f.high_priv_perms
        assert "secrets:read" in f.high_priv_perms
        assert "model:read"   not in f.high_priv_perms

    def test_save_json(self, tmp_path):
        det    = StaleEntitlementDetector()
        rec    = EntitlementRecord("x", {"model:read"}, self._ago(10), self._ago(100))
        report = det.scan([rec])
        p      = tmp_path / "stale.json"
        report.save_json(p)
        data = json.loads(p.read_text())
        assert "findings" in data


# ── PeerGroupAnomalyDetector ──────────────────────────────────────────────────

class TestPeerGroupAnomalyDetector:

    def _members(self):
        return [
            PeerGroupMember("alice", {"a","b","c"},                  team="nlp"),
            PeerGroupMember("bob",   {"a","b","c"},                  team="nlp"),
            PeerGroupMember("carol", {"a","b","c","d","e","f","g"}, team="nlp"),  # outlier
            PeerGroupMember("dave",  {"x","y"},                      team="cv"),
            PeerGroupMember("eve",   {"x","y"},                      team="cv"),
        ]

    def test_outlier_flagged(self):
        det    = PeerGroupAnomalyDetector(excess_warn=2, excess_critical=5)
        report = det.analyse(self._members())
        carol  = next(f for f in report.findings if f.principal == "carol")
        assert carol.severity in ("WARNING", "CRITICAL")

    def test_normal_members_ok(self):
        det    = PeerGroupAnomalyDetector(excess_warn=2)
        report = det.analyse(self._members())
        alice  = next(f for f in report.findings if f.principal == "alice")
        assert alice.severity == "OK"

    def test_excess_permissions_listed(self):
        det    = PeerGroupAnomalyDetector(excess_warn=2)
        report = det.analyse(self._members())
        carol  = next(f for f in report.findings if f.principal == "carol")
        assert len(carol.excess_permissions) > 0
        for p in carol.excess_permissions:
            assert p not in {"a", "b", "c"}

    def test_small_group_ok(self):
        det    = PeerGroupAnomalyDetector(min_group_size=3)
        single = [PeerGroupMember("solo", {"a","b"}, team="solo-team")]
        report = det.analyse(single)
        assert report.findings[0].severity == "OK"
        assert "too small" in report.findings[0].detail

    def test_jaccard_distance_computed(self):
        det    = PeerGroupAnomalyDetector()
        members = [
            PeerGroupMember("a", {"x","y","z","w","v"}, team="t"),
            PeerGroupMember("b", {"x","y"},             team="t"),
            PeerGroupMember("c", {"x","y"},             team="t"),
        ]
        report = det.analyse(members)
        a_find = next(f for f in report.findings if f.principal == "a")
        assert a_find.jaccard_distance > 0

    def test_separate_groups_analysed(self):
        det    = PeerGroupAnomalyDetector()
        report = det.analyse(self._members())
        teams  = {f.team for f in report.findings}
        assert "nlp" in teams
        assert "cv"  in teams

    def test_save_json(self, tmp_path):
        det    = PeerGroupAnomalyDetector()
        report = det.analyse(self._members())
        p      = tmp_path / "peer.json"
        report.save_json(p)
        data = json.loads(p.read_text())
        assert "findings" in data


# ── ReviewWorkflowEngine ──────────────────────────────────────────────────────

ENTITLEMENTS = [
    {"principal": "alice", "permissions": ["model:read"], "team": "nlp"},
    {"principal": "bob",   "permissions": ["data:write"], "team": "nlp"},
    {"principal": "carol", "permissions": ["model:deploy"], "team": "cv"},
]


class TestReviewWorkflowEngine:

    def _engine(self, audit=None):
        return ReviewWorkflowEngine(audit_path=audit)

    def _campaign(self, engine):
        return engine.create_campaign("Q1 Review", ENTITLEMENTS, "security-team")

    def test_create_campaign(self):
        eng = self._engine()
        c   = self._campaign(eng)
        assert c.status          == "open"
        assert len(c.items)      == 3
        assert c.campaign_id

    def test_assign_reviewer(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        item = c.items[0]
        ok   = eng.assign_reviewer(c.campaign_id, item.item_id, "reviewer-a")
        assert ok
        assert c.items[0].reviewer == "reviewer-a"
        assert c.status == "in_progress"

    def test_assign_all_by_team(self):
        eng     = self._engine()
        c       = self._campaign(eng)
        assigned = eng.assign_all(c.campaign_id,
                                   {"nlp": "reviewer-nlp", "cv": "reviewer-cv"})
        assert assigned == 3
        nlp_items = [i for i in c.items if i.team == "nlp"]
        assert all(i.reviewer == "reviewer-nlp" for i in nlp_items)

    def test_record_certify_decision(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        item = c.items[0]
        eng.assign_reviewer(c.campaign_id, item.item_id, "rev-a")
        ok = eng.record_decision(c.campaign_id, item.item_id,
                                  "certify", "rev-a", "Still needs access")
        assert ok
        assert c.items[0].decision == "certify"

    def test_record_revoke_decision(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        item = c.items[1]
        eng.assign_reviewer(c.campaign_id, item.item_id, "rev-a")
        eng.record_decision(c.campaign_id, item.item_id, "revoke", "rev-a",
                            "No longer in data engineering role")
        assert c.items[1].decision == "revoke"

    def test_invalid_decision_raises(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        item = c.items[0]
        with pytest.raises(ValueError):
            eng.record_decision(c.campaign_id, item.item_id, "maybe", "rev-a")

    def test_escalate_overdue(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        # Mark campaign deadline as past
        c.deadline = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        escalated  = eng.escalate_overdue(c.campaign_id)
        assert len(escalated) == 3
        assert all(i.escalated for i in escalated)
        assert c.status == "escalated"

    def test_escalate_not_triggered_before_deadline(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        escalated = eng.escalate_overdue(c.campaign_id)
        assert len(escalated) == 0

    def test_close_campaign_returns_revoke_list(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        for i, item in enumerate(c.items):
            eng.assign_reviewer(c.campaign_id, item.item_id, "rev")
            decision = "revoke" if i == 1 else "certify"
            eng.record_decision(c.campaign_id, item.item_id, decision, "rev")
        to_revoke = eng.close_campaign(c.campaign_id)
        assert len(to_revoke) == 1
        assert to_revoke[0].principal == "bob"
        assert c.status == "closed"

    def test_progress(self):
        eng  = self._engine()
        c    = self._campaign(eng)
        item = c.items[0]
        eng.assign_reviewer(c.campaign_id, item.item_id, "rev")
        eng.record_decision(c.campaign_id, item.item_id, "certify", "rev")
        prog = eng.progress(c.campaign_id)
        assert prog.decided  == 1
        assert prog.pending  == 2
        assert prog.completion_pct == pytest.approx(33.3, abs=0.2)

    def test_audit_log_written(self, tmp_path):
        log = tmp_path / "workflow.jsonl"
        eng = self._engine(audit=log)
        c   = self._campaign(eng)
        item = c.items[0]
        eng.record_decision(c.campaign_id, item.item_id, "certify", "rev")
        events = {json.loads(l)["event"] for l in log.read_text().splitlines() if l}
        assert "campaign_created"  in events
        assert "decision_recorded" in events


# ── AccessCertificationReporter ───────────────────────────────────────────────

class TestAccessCertificationReporter:

    def _closed_campaign(self):
        eng = ReviewWorkflowEngine()
        c   = eng.create_campaign("Q1 2026", ENTITLEMENTS, "security-team")
        for i, item in enumerate(c.items):
            eng.assign_reviewer(c.campaign_id, item.item_id, f"reviewer-{i%2}")
            eng.record_decision(c.campaign_id, item.item_id,
                                "revoke" if i == 2 else "certify",
                                f"reviewer-{i%2}", "reason")
        eng.close_campaign(c.campaign_id)
        return c

    def test_report_totals(self):
        reporter = AccessCertificationReporter()
        report   = reporter.generate(self._closed_campaign(), "compliance-team")
        assert report.total_entitlements == 3
        assert report.certified          == 2
        assert report.revoked            == 1
        assert report.pending            == 0
        assert report.completion_pct     == 100.0

    def test_remediation_list_populated(self):
        reporter = AccessCertificationReporter()
        report   = reporter.generate(self._closed_campaign(), "compliance-team")
        assert len(report.remediation_list) == 1
        assert report.remediation_list[0].principal == "carol"

    def test_reviewer_stats(self):
        reporter = AccessCertificationReporter()
        report   = reporter.generate(self._closed_campaign(), "compliance-team")
        assert len(report.reviewer_stats) > 0
        total_decided = sum(s.decided for s in report.reviewer_stats)
        assert total_decided == 3

    def test_sign_off(self):
        reporter = AccessCertificationReporter()
        report   = reporter.generate(self._closed_campaign(), "compliance-team")
        report.sign_off("ciso@company.com", notes="Q1 2026 review complete")
        assert report.signed_off_by == "ciso@company.com"
        assert report.signed_off_at
        assert "Q1 2026" in report.sign_off_notes

    def test_summary_string(self):
        reporter = AccessCertificationReporter()
        report   = reporter.generate(self._closed_campaign(), "compliance-team")
        s        = report.summary()
        assert "Q1 2026" in s
        assert "certified" in s

    def test_save_json(self, tmp_path):
        reporter = AccessCertificationReporter()
        report   = reporter.generate(self._closed_campaign(), "compliance-team")
        report.sign_off("auditor@company.com")
        p = tmp_path / "cert_report.json"
        report.save_json(p)
        data = json.loads(p.read_text())
        assert "remediation_list"  in data
        assert "reviewer_stats"    in data
        assert "signed_off_by"     in data

    def test_high_priv_counts(self):
        reporter = AccessCertificationReporter()
        report   = reporter.generate(self._closed_campaign(), "compliance-team")
        # carol has model:deploy which is high-priv and was revoked
        assert report.high_priv_revoked >= 1
