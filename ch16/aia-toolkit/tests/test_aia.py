"""
tests/test_aia.py
AI Fortress · Chapter 16 · Code Sample 16.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from pathlib import Path
from impact_register import ImpactRegister
from stakeholder_impact_scorer import StakeholderImpactScorer
from regulatory_classifier import RegulatoryClassifier


# ── ImpactRegister ────────────────────────────────────────────────────────────

class TestImpactRegister:

    def test_add_entry(self):
        reg   = ImpactRegister("loan-model")
        entry = reg.add("direct", "high", "low-income applicants",
                        "Denial rate higher for low-income group", 4, 4)
        assert entry.impact_id
        assert entry.risk_score == 16

    def test_entries_stored(self):
        reg = ImpactRegister("m")
        reg.add("direct", "moderate", "women", "Lower approval rate", 3, 3)
        reg.add("indirect", "low", "public", "Reduced competition", 2, 2)
        assert len(reg.entries()) == 2

    def test_filter_by_status(self):
        reg = ImpactRegister("m")
        e1  = reg.add("direct", "high", "group-a", "desc", 4, 4)
        reg.add("direct", "low", "group-b", "desc", 1, 1)
        reg.mitigate(e1.impact_id, "Apply reweighing")
        assert len(reg.entries("open")) == 1
        assert len(reg.entries("mitigated")) == 1

    def test_high_risk_entries(self):
        reg = ImpactRegister("m")
        reg.add("direct", "critical", "g", "d", 5, 5)   # score 25
        reg.add("direct", "low",  "g", "d", 1, 1)       # score 1
        assert len(reg.high_risk_entries(15)) == 1

    def test_mitigate_unknown_raises(self):
        reg = ImpactRegister("m")
        with pytest.raises(KeyError):
            reg.mitigate("nonexistent", "fix")

    def test_persist_to_json(self, tmp_path):
        p   = tmp_path / "register.json"
        reg = ImpactRegister("m", p)
        reg.add("direct", "high", "g", "d", 3, 3)
        reg2 = ImpactRegister("m", p)
        assert len(reg2.entries()) == 1

    def test_risk_score_capped(self):
        reg   = ImpactRegister("m")
        entry = reg.add("direct", "critical", "g", "d", 10, 10)  # capped to 5x5
        assert entry.risk_score == 25


# ── StakeholderImpactScorer ───────────────────────────────────────────────────

class TestStakeholderImpactScorer:

    def _stakeholders(self):
        return [
            {"name": "loan applicants",
             "scores": {"autonomy": 3, "fairness": 4, "economic": 4}},
            {"name": "bank staff",
             "scores": {"autonomy": 1, "economic": 2}},
        ]

    def test_returns_matrix(self):
        scorer = StakeholderImpactScorer()
        matrix = scorer.score("loan-model", self._stakeholders())
        assert len(matrix.stakeholders) == 2

    def test_total_score_computed(self):
        scorer = StakeholderImpactScorer()
        matrix = scorer.score("m", self._stakeholders())
        for sh in matrix.stakeholders:
            assert sh.total_score == sum(sh.scores.values())

    def test_critical_dims_detected(self):
        scorer = StakeholderImpactScorer()
        stakeholders = [{"name": "g", "scores": {"safety": 5}}]
        matrix = scorer.score("m", stakeholders)
        assert "safety" in matrix.critical_dims

    def test_overall_level_populated(self):
        scorer = StakeholderImpactScorer()
        matrix = scorer.score("m", self._stakeholders())
        assert matrix.overall_level in ["none","minimal","low","moderate","high","critical"]

    def test_highest_dimension_set(self):
        scorer = StakeholderImpactScorer()
        sh     = [{"name": "g", "scores": {"fairness": 5, "autonomy": 1}}]
        matrix = scorer.score("m", sh)
        assert matrix.stakeholders[0].highest_dimension == "fairness"


# ── RegulatoryClassifier ──────────────────────────────────────────────────────

class TestRegulatoryClassifier:

    def test_high_risk_credit(self):
        clf    = RegulatoryClassifier()
        result = clf.classify("loan-engine", ["credit scoring for personal loans"])
        assert result.eu_ai_act_tier == "high_risk"
        assert len(result.obligations) > 0

    def test_employment_high_risk(self):
        clf    = RegulatoryClassifier()
        result = clf.classify("hr-screener", ["recruitment screening of job candidates"])
        assert result.eu_ai_act_tier == "high_risk"

    def test_minimal_risk(self):
        clf    = RegulatoryClassifier()
        result = clf.classify("spam-filter", ["spam email classification"])
        assert result.eu_ai_act_tier == "minimal_risk"

    def test_sector_finance_flag(self):
        clf    = RegulatoryClassifier()
        result = clf.classify("m", ["loan decision"], sectors=["finance"])
        assert any("ECOA" in f for f in result.sector_flags)

    def test_sector_health_flag(self):
        clf    = RegulatoryClassifier()
        result = clf.classify("m", ["patient triage"], sectors=["healthcare"])
        assert any("HIPAA" in f for f in result.sector_flags)

    def test_summary_string(self):
        clf    = RegulatoryClassifier()
        result = clf.classify("m", ["credit scoring"])
        assert result.system_name in result.summary

    def test_matched_categories_populated(self):
        clf    = RegulatoryClassifier()
        result = clf.classify("m", ["credit scoring for loans"])
        assert len(result.matched_categories) >= 1
