"""
tests/test_maturity_assessment.py
AI Fortress · Chapter 14 · Code Sample 14.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from maturity_scorer import MaturityScorer
from gap_analyser import GapAnalyser
from maturity_model import CAPABILITIES, DOMAINS


_LOW_SCORES  = {c.capability_id: 1 for c in CAPABILITIES}
_HIGH_SCORES = {c.capability_id: 4 for c in CAPABILITIES}
_MID_SCORES  = {c.capability_id: 2 for c in CAPABILITIES}


# ── MaturityScorer ─────────────────────────────────────────────────────────────

class TestMaturityScorer:

    def test_assess_returns_report(self):
        r = MaturityScorer().assess(_MID_SCORES)
        assert r.assessment_id
        assert r.overall_score > 0

    def test_low_scores_give_low_overall(self):
        r = MaturityScorer().assess(_LOW_SCORES)
        assert r.overall_score < 2.0

    def test_high_scores_give_high_overall(self):
        r = MaturityScorer().assess(_HIGH_SCORES)
        assert r.overall_score >= 3.5

    def test_all_domains_present(self):
        r = MaturityScorer().assess(_MID_SCORES)
        domain_names = {d.domain for d in r.domain_scores}
        for domain in DOMAINS:
            assert domain in domain_names

    def test_cap_scores_all_capabilities(self):
        r = MaturityScorer().assess(_MID_SCORES)
        ids = {c.capability_id for c in r.capability_scores}
        for cap in CAPABILITIES:
            assert cap.capability_id in ids

    def test_missing_capability_defaults_to_zero(self):
        r = MaturityScorer().assess({})
        for cs in r.capability_scores:
            assert cs.current_level == 0

    def test_critical_gap_detected(self):
        # Target is 3, current is 0 → gap = 3 → critical
        scores = {c.capability_id: 0 for c in CAPABILITIES}
        r = MaturityScorer().assess(scores)
        assert len(r.critical_gaps) > 0

    def test_no_critical_gap_when_at_target(self):
        # Default target = 3; score 3 everywhere
        scores = {c.capability_id: 3 for c in CAPABILITIES}
        r = MaturityScorer().assess(scores)
        assert len(r.critical_gaps) == 0

    def test_roadmap_has_waves(self):
        r = MaturityScorer().assess(_LOW_SCORES)
        assert len(r.roadmap) >= 1
        for wave in r.roadmap:
            assert "wave" in wave and "items" in wave

    def test_grade_range(self):
        for scores in [_LOW_SCORES, _MID_SCORES, _HIGH_SCORES]:
            r = MaturityScorer().assess(scores)
            assert r.overall_grade in "ABCDF"

    def test_summary_string(self):
        r = MaturityScorer(organisation="TestOrg").assess(_MID_SCORES)
        assert "TestOrg" in r.summary()

    def test_save_json(self, tmp_path):
        r = MaturityScorer().assess(_MID_SCORES)
        p = tmp_path / "maturity.json"
        r.save_json(p)
        data = json.loads(p.read_text())
        assert "overall_score" in data

    def test_custom_target_level(self):
        # Custom target of 5 for GOV-01 → larger gap
        r_default = MaturityScorer().assess({"GOV-01": 2})
        r_custom  = MaturityScorer(target_levels={"GOV-01": 5}).assess({"GOV-01": 2})
        default_gap = next(c.gap for c in r_default.capability_scores if c.capability_id == "GOV-01")
        custom_gap  = next(c.gap for c in r_custom.capability_scores  if c.capability_id == "GOV-01")
        assert custom_gap > default_gap

    def test_domain_grade_populated(self):
        r = MaturityScorer().assess(_MID_SCORES)
        for d in r.domain_scores:
            assert d.grade in "ABCDF"

    def test_overall_gap_nonneg(self):
        r = MaturityScorer().assess(_HIGH_SCORES)
        assert r.overall_gap >= 0


# ── GapAnalyser ────────────────────────────────────────────────────────────────

class TestGapAnalyser:

    def _report(self, scores=None):
        return MaturityScorer(organisation="TestOrg").assess(scores or _LOW_SCORES)

    def test_analyse_returns_report(self):
        r  = self._report()
        ga = GapAnalyser().analyse(r)
        assert ga.total_gaps >= 0

    def test_gaps_sorted_by_priority(self):
        ga   = GapAnalyser().analyse(self._report())
        prios = [g.priority for g in ga.gaps]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        assert prios == sorted(prios, key=lambda p: order[p])

    def test_sector_benchmark_loaded(self):
        ga = GapAnalyser(sector="financial_services").analyse(self._report())
        # Low scores should show up as below benchmark
        assert len(ga.below_benchmark) >= 1

    def test_unknown_sector_falls_back(self):
        ga = GapAnalyser(sector="unknown_sector").analyse(self._report())
        assert ga.sector == "cross_sector"

    def test_remediation_steps_populated(self):
        ga = GapAnalyser().analyse(self._report())
        for gap in ga.gaps:
            assert isinstance(gap.remediation_steps, list)

    def test_no_gaps_when_at_target(self):
        scores = {c.capability_id: 3 for c in CAPABILITIES}
        r  = MaturityScorer().assess(scores)
        ga = GapAnalyser().analyse(r)
        assert ga.total_gaps == 0

    def test_counts_consistent(self):
        ga = GapAnalyser().analyse(self._report())
        assert ga.critical_count + ga.high_count + ga.medium_count <= ga.total_gaps

    def test_vs_benchmark_sign(self):
        # High scores → above benchmark for most capabilities
        r  = MaturityScorer().assess(_HIGH_SCORES)
        ga = GapAnalyser().analyse(r)
        # When scoring high, few should be below benchmark
        assert len(ga.below_benchmark) < len(CAPABILITIES)
