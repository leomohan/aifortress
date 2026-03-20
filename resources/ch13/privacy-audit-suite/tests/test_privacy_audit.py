"""
tests/test_privacy_audit.py
AI Fortress · Chapter 13 · Code Sample 13.D
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest, random
from pathlib import Path

from membership_inference import MembershipInferenceAuditor
from attribute_inference import AttributeInferenceAuditor
from canary_auditor import CanaryAuditor
from audit_report import PrivacyAuditReporter


# ── MembershipInferenceAuditor ────────────────────────────────────────────────

class TestMembershipInferenceAuditor:

    def test_perfect_separation_high_auc(self):
        aud    = MembershipInferenceAuditor()
        result = aud.audit(
            member_confidences    = [0.9] * 100,
            nonmember_confidences = [0.4] * 100,
        )
        assert result.attack_auc > 0.9
        assert result.severity in ("critical", "high")

    def test_identical_distributions_low_auc(self):
        aud    = MembershipInferenceAuditor()
        confs  = [0.7] * 100
        result = aud.audit(confs, confs)
        assert abs(result.attack_auc - 0.5) < 0.05

    def test_advantage_is_tpr_minus_fpr(self):
        aud    = MembershipInferenceAuditor()
        result = aud.audit([0.9]*50, [0.5]*50)
        assert abs(result.advantage - (result.tpr_at_threshold - result.fpr_at_threshold)) < 0.01

    def test_severity_tiers(self):
        aud = MembershipInferenceAuditor()
        r1  = aud.audit([0.95]*100, [0.3]*100)
        r2  = aud.audit([0.7]*100,  [0.6]*100)
        assert r1.severity in ("critical", "high")
        assert r2.severity in ("moderate", "low")

    def test_n_members_recorded(self):
        aud    = MembershipInferenceAuditor()
        result = aud.audit([0.8]*30, [0.5]*70)
        assert result.n_members     == 30
        assert result.n_non_members == 70

    def test_summary_string(self):
        aud    = MembershipInferenceAuditor()
        result = aud.audit([0.9]*50, [0.5]*50)
        assert "AUC" in result.summary()


# ── AttributeInferenceAuditor ─────────────────────────────────────────────────

class TestAttributeInferenceAuditor:

    def test_high_gap_high_risk(self):
        aud  = AttributeInferenceAuditor()
        risk = aud.audit(
            "gender",
            [1]*100 + [0]*100,
            [0.9]*100 + [0.3]*100,
        )
        assert risk.risk_score > 0.5
        assert risk.severity in ("critical", "high")

    def test_no_gap_low_risk(self):
        aud  = AttributeInferenceAuditor()
        risk = aud.audit("age_group", [1]*50 + [0]*50, [0.7]*100)
        assert risk.risk_score == 0.0

    def test_single_class_returns_zero_risk(self):
        aud  = AttributeInferenceAuditor()
        risk = aud.audit("feature", [1]*100, [0.8]*100)
        assert risk.risk_score == 0.0

    def test_mismatched_lengths_raise(self):
        aud = AttributeInferenceAuditor()
        with pytest.raises(ValueError):
            aud.audit("x", [1, 0], [0.5])

    def test_base_rate_recorded(self):
        aud  = AttributeInferenceAuditor()
        risk = aud.audit("x", [1]*30 + [0]*70, [0.8]*100)
        assert abs(risk.base_rate - 0.30) < 0.01

    def test_detail_contains_gap(self):
        aud  = AttributeInferenceAuditor()
        risk = aud.audit("y", [1]*50 + [0]*50, [0.9]*50 + [0.5]*50)
        assert "gap" in risk.detail.lower()


# ── CanaryAuditor ─────────────────────────────────────────────────────────────

class TestCanaryAuditor:

    def test_high_confidence_canaries_high_exposure(self):
        aud    = CanaryAuditor()
        report = aud.audit(
            canary_confidences    = [0.999] * 5,
            noncanary_confidences = [0.5]  * 1000,
        )
        assert report.max_exposure_score > 0
        assert report.confidence_lift > 0

    def test_low_confidence_canaries_low_exposure(self):
        aud    = CanaryAuditor()
        report = aud.audit(
            canary_confidences    = [0.5] * 5,
            noncanary_confidences = [0.5] * 100,
        )
        assert report.severity in ("low", "moderate")

    def test_canary_ids_used(self):
        aud    = CanaryAuditor()
        report = aud.audit([0.9, 0.8], [0.5]*50, canary_ids=["c-001", "c-002"])
        ids    = {r.canary_id for r in report.canary_results}
        assert ids == {"c-001", "c-002"}

    def test_empty_canaries_raises(self):
        aud = CanaryAuditor()
        with pytest.raises(ValueError):
            aud.audit([], [0.5]*100)

    def test_n_counts(self):
        aud    = CanaryAuditor()
        report = aud.audit([0.9]*3, [0.5]*97)
        assert report.n_canaries     == 3
        assert report.n_non_canaries == 97

    def test_summary_string(self):
        aud    = CanaryAuditor()
        report = aud.audit([0.9]*5, [0.5]*95)
        assert "canary" in report.summary().lower()


# ── PrivacyAuditReporter ──────────────────────────────────────────────────────

class TestPrivacyAuditReporter:

    def _mia(self):
        return MembershipInferenceAuditor().audit([0.9]*50, [0.5]*50)

    def _attr(self):
        return AttributeInferenceAuditor().audit("income", [1]*50+[0]*50,
                                                  [0.9]*50+[0.4]*50)

    def _canary(self):
        return CanaryAuditor().audit([0.999]*3, [0.5]*97)

    def test_generate_full_report(self):
        reporter = PrivacyAuditReporter()
        report   = reporter.generate(
            "fraud-model", "2.0.0", "privacy-team",
            mia_result=self._mia(), attribute_risks=[self._attr()],
            canary_report=self._canary(),
        )
        assert report.report_id
        assert len(report.findings_summary) == 3

    def test_overall_severity_max(self):
        reporter = PrivacyAuditReporter()
        report   = reporter.generate(
            "m", "1.0", "team",
            mia_result=MembershipInferenceAuditor().audit([0.99]*100, [0.3]*100),
        )
        assert report.overall_severity in ("critical", "high")

    def test_no_findings_low_severity(self):
        reporter = PrivacyAuditReporter()
        report   = reporter.generate("m", "1.0", "team")
        assert report.overall_severity == "low"

    def test_recommendations_populated(self):
        reporter = PrivacyAuditReporter()
        report   = reporter.generate("m", "1.0", "team",
                    mia_result=MembershipInferenceAuditor().audit([0.95]*100,[0.3]*100))
        assert any("differential privacy" in r.lower() for r in report.recommendations)

    def test_save_json(self, tmp_path):
        reporter = PrivacyAuditReporter()
        report   = reporter.generate("m", "1.0", "team", mia_result=self._mia())
        p        = tmp_path / "audit.json"
        report.save_json(p)
        data     = json.loads(p.read_text())
        assert "overall_severity" in data

    def test_summary_string(self):
        reporter = PrivacyAuditReporter()
        report   = reporter.generate("fraud", "2.0", "team", mia_result=self._mia())
        assert "fraud" in report.summary()
