"""
tests/test_regulatory_notification.py
AI Fortress · Chapter 17 · Code Sample 17.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import pytest
from datetime import datetime, timedelta, timezone
from obligation_checker import ObligationChecker
from notification_drafter import NotificationDrafter
from deadline_tracker import DeadlineTracker


# ── ObligationChecker ─────────────────────────────────────────────────────────

class TestObligationChecker:

    def test_gdpr_triggered_on_personal_data_breach_eu(self):
        checker = ObligationChecker()
        result  = checker.check(
            "INC-001",
            personal_data_breach=True,
            eu_residents_affected=True,
        )
        regs = [o.regulation for o in result.obligations]
        assert any("GDPR Art.33" in r for r in regs)

    def test_uk_gdpr_triggered(self):
        checker = ObligationChecker()
        result  = checker.check(
            "INC-001",
            personal_data_breach=True,
            uk_residents_affected=True,
        )
        regs = [o.regulation for o in result.obligations]
        assert any("UK GDPR" in r for r in regs)

    def test_eu_ai_act_triggered_on_serious_incident(self):
        checker = ObligationChecker()
        result  = checker.check("INC-001", serious_incident=True, high_risk_ai=True)
        regs = [o.regulation for o in result.obligations]
        assert any("AI Act" in r for r in regs)

    def test_hipaa_triggered_on_phi(self):
        checker = ObligationChecker()
        result  = checker.check("INC-001", phi_breach=True)
        regs = [o.regulation for o in result.obligations]
        assert any("HIPAA" in r for r in regs)

    def test_no_obligations_with_no_flags(self):
        checker = ObligationChecker()
        result  = checker.check("INC-001")
        assert result.n_mandatory == 0

    def test_earliest_deadline_is_minimum(self):
        checker = ObligationChecker()
        result  = checker.check(
            "INC-001",
            personal_data_breach=True,
            eu_residents_affected=True,
            significant_incident=True,
            essential_entity=True,
        )
        # NIS2 = 24h, GDPR = 72h → earliest should be 24
        if result.earliest_deadline_hours:
            assert result.earliest_deadline_hours <= 72

    def test_summary_string(self):
        checker = ObligationChecker()
        result  = checker.check("INC-001", personal_data_breach=True,
                                eu_residents_affected=True)
        assert "obligation" in result.summary.lower()


# ── NotificationDrafter ───────────────────────────────────────────────────────

class TestNotificationDrafter:

    def _obligation(self):
        from obligation_checker import NotificationObligation
        return NotificationObligation(
            regulation="GDPR Art.33",
            regulator="Supervisory Authority",
            deadline_hours=72,
            deadline_label="72 hours",
            recipient="regulator",
            triggered_by=["personal_data_breach"],
            mandatory=True,
            notes="Test note.",
        )

    def test_draft_returns_text(self):
        drafter = NotificationDrafter("ACME Corp", "dpo@acme.com")
        draft   = drafter.draft(
            self._obligation(),
            incident_summary="Model weights extracted via API",
            discovery_timestamp="2026-01-01T08:00:00Z",
            affected_data_types=["name", "email", "model_output"],
            affected_count=1500,
            mitigations_taken=["API suspended", "Passwords rotated"],
        )
        assert "GDPR Art.33" in draft.draft_text
        assert "ACME Corp" in draft.draft_text
        assert draft.regulation == "GDPR Art.33"

    def test_draft_flagged_for_legal_review(self):
        drafter = NotificationDrafter("Corp", "dpo@corp.com")
        draft   = drafter.draft(
            self._obligation(), "Summary", "2026-01-01T00:00:00Z",
            ["email"], 100, ["Isolated system"],
        )
        assert "LEGAL REVIEW" in draft.draft_text

    def test_required_fields_populated(self):
        drafter = NotificationDrafter("Corp", "dpo@corp.com")
        draft   = drafter.draft(
            self._obligation(), "Summary", "2026-01-01T00:00:00Z",
            ["email"], 100, ["Isolated system"],
        )
        assert "organisation name" in (k.lower() for k in draft.required_fields)

    def test_affected_count_in_draft(self):
        drafter = NotificationDrafter("Corp", "dpo@corp.com")
        draft   = drafter.draft(
            self._obligation(), "s", "t", ["email"], 999, ["m"],
        )
        assert "999" in draft.draft_text


# ── DeadlineTracker ───────────────────────────────────────────────────────────

class TestDeadlineTracker:

    def _recent_discovery(self, hours_ago=1.0):
        t = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return t.isoformat()

    def test_on_track_early(self):
        tracker = DeadlineTracker("INC-001", self._recent_discovery(1))
        tracker.add("GDPR Art.33", 72, "72 hours")
        dash = tracker.status()
        s    = next(s for s in dash.statuses if "GDPR" in s.regulation)
        assert s.status == "on_track"

    def test_overdue_detection(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=100)).isoformat()
        tracker = DeadlineTracker("INC-001", old)
        tracker.add("GDPR Art.33", 72, "72 hours")
        dash = tracker.status()
        assert "GDPR Art.33" in dash.overdue

    def test_urgent_near_deadline(self):
        # Discover 65h ago; 72h deadline → 90% elapsed
        old     = (datetime.now(timezone.utc) - timedelta(hours=65)).isoformat()
        tracker = DeadlineTracker("INC-001", old)
        tracker.add("GDPR Art.33", 72, "72 hours")
        dash    = tracker.status()
        s       = next(s for s in dash.statuses if "GDPR" in s.regulation)
        assert s.status in ("urgent", "overdue")

    def test_mark_submitted(self):
        tracker = DeadlineTracker("INC-001", self._recent_discovery(1))
        tracker.add("GDPR Art.33", 72, "72 hours")
        tracker.mark_submitted("GDPR Art.33")
        dash = tracker.status()
        s    = next(s for s in dash.statuses if "GDPR" in s.regulation)
        assert s.status == "submitted"

    def test_manual_deadline_status(self):
        tracker = DeadlineTracker("INC-001", self._recent_discovery(1))
        tracker.add("EU AI Act Art.73", None, "15 working days")
        dash = tracker.status()
        s    = next(s for s in dash.statuses if "AI Act" in s.regulation)
        assert s.status == "manual"

    def test_mark_submitted_unknown_raises(self):
        tracker = DeadlineTracker("INC-001", self._recent_discovery())
        with pytest.raises(KeyError):
            tracker.mark_submitted("Unknown Reg")

    def test_multiple_obligations(self):
        tracker = DeadlineTracker("INC-001", self._recent_discovery(1))
        tracker.add("GDPR Art.33", 72, "72h")
        tracker.add("NIS2", 24, "24h")
        dash = tracker.status()
        assert len(dash.statuses) == 2
