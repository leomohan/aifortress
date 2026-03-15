"""
tests/test_fairness_eval.py
AI Fortress · Chapter 16 · Code Sample 16.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest, random
from fairness_metrics import FairnessEvaluator
from intersectional_fairness import IntersectionalFairnessEvaluator
from fairness_report import FairnessReportBuilder


def _fair_data(n=300, seed=1):
    random.seed(seed)
    groups = (["A"] * (n // 2)) + (["B"] * (n // 2))
    y_true = [random.randint(0, 1) for _ in range(n)]
    y_pred = y_true[:]   # perfect predictions → fair
    return y_true, y_pred, groups


def _biased_data(n=300, seed=2):
    """Group B has 50% lower positive rate than A."""
    random.seed(seed)
    y_true, y_pred, groups = [], [], []
    for i in range(n):
        g   = "A" if i < n // 2 else "B"
        yt  = random.randint(0, 1)
        yp  = yt if g == "A" else (0 if random.random() < 0.5 else yt)
        groups.append(g); y_true.append(yt); y_pred.append(yp)
    return y_true, y_pred, groups


# ── FairnessEvaluator ─────────────────────────────────────────────────────────

class TestFairnessEvaluator:

    def test_fair_data_grade_a(self):
        ev = FairnessEvaluator()
        yt, yp, g = _fair_data()
        result = ev.evaluate(yt, yp, g)
        assert result.overall_fairness_grade in ("A", "B")
        assert len(result.violations) == 0

    def test_biased_data_violations(self):
        ev = FairnessEvaluator(dpd_threshold=0.05)
        yt, yp, g = _biased_data()
        result = ev.evaluate(yt, yp, g)
        assert len(result.violations) > 0

    def test_reference_group_is_largest(self):
        yt, yp, g = _fair_data(300)
        ev     = FairnessEvaluator()
        result = ev.evaluate(yt, yp, g)
        assert result.reference_group in ("A", "B")

    def test_explicit_reference_group(self):
        yt, yp, g = _fair_data()
        ev     = FairnessEvaluator()
        result = ev.evaluate(yt, yp, g, reference="B")
        assert result.reference_group == "B"

    def test_group_metrics_populated(self):
        yt, yp, g = _fair_data()
        ev     = FairnessEvaluator()
        result = ev.evaluate(yt, yp, g)
        assert "A" in result.group_metrics
        assert "B" in result.group_metrics

    def test_dpd_is_nonneg(self):
        yt, yp, g = _biased_data()
        ev     = FairnessEvaluator()
        result = ev.evaluate(yt, yp, g)
        for v in result.demographic_parity_diff.values():
            assert v >= 0

    def test_worst_dpd_helper(self):
        yt, yp, g = _biased_data()
        ev     = FairnessEvaluator()
        result = ev.evaluate(yt, yp, g)
        assert result.worst_dpd() >= 0

    def test_mismatched_lengths_raise(self):
        ev = FairnessEvaluator()
        with pytest.raises(ValueError):
            ev.evaluate([0, 1], [0], ["A", "B"])

    def test_summary_string(self):
        yt, yp, g = _fair_data()
        ev     = FairnessEvaluator()
        result = ev.evaluate(yt, yp, g)
        assert "grade" in result.summary().lower() or "Fairness" in result.summary()

    def test_calibration_gap_with_scores(self):
        yt, yp, g = _fair_data()
        scores = [float(p) for p in yp]
        ev     = FairnessEvaluator()
        result = ev.evaluate(yt, yp, g, scores=scores)
        for v in result.calibration_gap.values():
            assert v >= 0


# ── IntersectionalFairnessEvaluator ──────────────────────────────────────────

class TestIntersectionalFairnessEvaluator:

    def _data(self, n=200, seed=5):
        random.seed(seed)
        y_true = [random.randint(0, 1) for _ in range(n)]
        y_pred = [random.randint(0, 1) for _ in range(n)]
        attrs  = {
            "gender": [random.choice(["M", "F"]) for _ in range(n)],
            "age":    [random.choice(["young", "old"]) for _ in range(n)],
        }
        return y_true, y_pred, attrs

    def test_returns_report(self):
        ev = IntersectionalFairnessEvaluator(min_subgroup_size=10)
        yt, yp, attrs = self._data()
        report = ev.evaluate(yt, yp, attrs)
        assert report.n_subgroups >= 1

    def test_grade_populated(self):
        ev = IntersectionalFairnessEvaluator(min_subgroup_size=10)
        yt, yp, attrs = self._data()
        report = ev.evaluate(yt, yp, attrs)
        assert report.grade in "ABCDF"

    def test_parity_range_nonneg(self):
        ev = IntersectionalFairnessEvaluator(min_subgroup_size=10)
        yt, yp, attrs = self._data()
        report = ev.evaluate(yt, yp, attrs)
        assert report.parity_range >= 0

    def test_worst_best_subgroups_set(self):
        ev = IntersectionalFairnessEvaluator(min_subgroup_size=10)
        yt, yp, attrs = self._data()
        report = ev.evaluate(yt, yp, attrs)
        if report.n_subgroups > 0:
            assert report.worst_subgroup
            assert report.best_subgroup


# ── FairnessReportBuilder ─────────────────────────────────────────────────────

class TestFairnessReportBuilder:

    def _group_fair(self):
        yt, yp, g = _fair_data()
        return FairnessEvaluator().evaluate(yt, yp, g)

    def _group_biased(self):
        yt, yp, g = _biased_data()
        return FairnessEvaluator(dpd_threshold=0.05).evaluate(yt, yp, g)

    def test_build_report(self):
        builder = FairnessReportBuilder()
        report  = builder.build("fraud", "1.0", "gender", self._group_fair())
        assert report.report_id
        assert report.model_name == "fraud"

    def test_high_risk_regulatory_flag(self):
        builder = FairnessReportBuilder()
        report  = builder.build("loan", "1.0", "race",
                                self._group_fair(), use_case="credit scoring")
        assert any("EU AI Act" in f for f in report.regulatory_flags)

    def test_violations_trigger_recommendations(self):
        builder = FairnessReportBuilder()
        report  = builder.build("m", "1.0", "gender", self._group_biased())
        assert len(report.recommendations) > 0

    def test_save_json(self, tmp_path):
        builder = FairnessReportBuilder()
        report  = builder.build("m", "1.0", "gender", self._group_fair())
        p       = tmp_path / "fairness.json"
        report.save_json(p)
        data    = json.loads(p.read_text())
        assert "overall_grade" in data

    def test_summary_string(self):
        builder = FairnessReportBuilder()
        report  = builder.build("fraud", "2.0", "age", self._group_fair())
        assert "fraud" in report.summary()

    def test_report_id_unique(self):
        builder = FairnessReportBuilder()
        r1 = builder.build("m", "1.0", "g", self._group_fair())
        r2 = builder.build("m", "1.0", "g", self._group_fair())
        assert r1.report_id != r2.report_id
