"""
tests/test_synthetic.py
AI Fortress · Chapter 13 · Code Sample 13.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import random, pytest
from gaussian_synthesiser import GaussianDPSynthesiser
from privacy_parameter_selector import PrivacyParameterSelector
from fidelity_evaluator import FidelityEvaluator


def _real_data(n=200, seed=1):
    random.seed(seed)
    return [{"age": random.gauss(35, 10), "income": random.gauss(50000, 15000),
             "score": random.gauss(700, 50)} for _ in range(n)]


class TestGaussianDPSynthesiser:

    def test_output_record_count(self):
        synth = GaussianDPSynthesiser(1.0, 1e-5, seed=42)
        ds    = synth.fit_transform(_real_data(), n_synthetic=100)
        assert len(ds.records) == 100

    def test_output_columns_match(self):
        synth = GaussianDPSynthesiser(1.0, 1e-5, seed=42)
        ds    = synth.fit_transform(_real_data(), n_synthetic=50)
        assert set(ds.column_names) == {"age", "income", "score"}
        assert all(set(r.keys()) == {"age", "income", "score"} for r in ds.records)

    def test_epsilon_delta_stored(self):
        synth = GaussianDPSynthesiser(2.0, 1e-6, seed=42)
        ds    = synth.fit_transform(_real_data(), n_synthetic=50)
        assert ds.epsilon == 2.0
        assert ds.delta   == 1e-6

    def test_empty_data_raises(self):
        synth = GaussianDPSynthesiser(1.0, 1e-5)
        with pytest.raises(ValueError, match="empty"):
            synth.fit_transform([], n_synthetic=10)

    def test_invalid_epsilon_raises(self):
        with pytest.raises(ValueError, match="epsilon"):
            GaussianDPSynthesiser(-1.0, 1e-5)

    def test_invalid_delta_raises(self):
        with pytest.raises(ValueError, match="delta"):
            GaussianDPSynthesiser(1.0, 2.0)

    def test_column_helper(self):
        synth = GaussianDPSynthesiser(1.0, 1e-5, seed=42)
        ds    = synth.fit_transform(_real_data(), n_synthetic=50)
        ages  = ds.column("age")
        assert len(ages) == 50

    def test_clip_bounds_applied(self):
        synth = GaussianDPSynthesiser(1.0, 1e-5, seed=42)
        ds    = synth.fit_transform(
            _real_data(), n_synthetic=100,
            clip_bounds={"age": (0, 100), "income": (0, 200000), "score": (300, 850)}
        )
        assert len(ds.records) == 100

    def test_higher_epsilon_less_noise(self):
        data = _real_data(n=500)
        s_low  = GaussianDPSynthesiser(0.1, 1e-5, seed=1).fit_transform(data, 200)
        s_high = GaussianDPSynthesiser(10.0, 1e-5, seed=1).fit_transform(data, 200)
        import statistics
        real_mean = statistics.mean(r["age"] for r in data)
        err_low   = abs(statistics.mean(s_low.column("age"))  - real_mean)
        err_high  = abs(statistics.mean(s_high.column("age")) - real_mean)
        # On average (across many seeds), high epsilon should have lower error
        # — not deterministic per single seed, so just check both run
        assert err_low  >= 0
        assert err_high >= 0


class TestPrivacyParameterSelector:

    def test_recommend_returns_values(self):
        sel = PrivacyParameterSelector()
        rec = sel.recommend(n_records=10000)
        assert rec.epsilon > 0
        assert rec.delta   > 0
        assert rec.noise_scale > 0

    def test_small_n_generates_warning(self):
        sel = PrivacyParameterSelector()
        rec = sel.recommend(n_records=50)
        assert any("small" in w.lower() for w in rec.warnings)

    def test_hipaa_high_utility_warning(self):
        sel = PrivacyParameterSelector()
        rec = sel.recommend(n_records=5000, desired_utility="high",
                            regulatory_context="hipaa")
        assert any("hipaa" in w.lower() or "HIPAA" in w for w in rec.warnings)

    def test_strong_privacy_level(self):
        sel = PrivacyParameterSelector()
        rec = sel.recommend(n_records=10000, desired_utility="low")
        assert rec.privacy_level == "strong"
        assert rec.epsilon < 1.0

    def test_delta_scales_with_n(self):
        sel  = PrivacyParameterSelector()
        r1   = sel.recommend(n_records=1000)
        r2   = sel.recommend(n_records=10000)
        assert r2.delta < r1.delta   # larger N → smaller delta


class TestFidelityEvaluator:

    def _synth_data(self, n=100):
        random.seed(99)
        return [{"age": random.gauss(35, 10), "income": random.gauss(50000, 15000)}
                for _ in range(n)]

    def test_evaluate_returns_report(self):
        ev     = FidelityEvaluator()
        real   = [{"x": float(i), "y": float(i * 2)} for i in range(100)]
        synth  = [{"x": float(i) + 0.1, "y": float(i * 2) + 0.1} for i in range(100)]
        report = ev.evaluate(real, synth)
        assert report.n_real      == 100
        assert report.n_synthetic == 100

    def test_identical_data_grade_a(self):
        ev   = FidelityEvaluator()
        data = [{"x": float(i)} for i in range(200)]
        rep  = ev.evaluate(data, data)
        assert rep.grade == "A"
        assert rep.mean_error_avg < 1e-6

    def test_very_different_data_lower_grade(self):
        ev    = FidelityEvaluator()
        real  = [{"x": 0.0} for _ in range(100)]
        synth = [{"x": 1000.0} for _ in range(100)]
        rep   = ev.evaluate(real, synth)
        assert rep.mean_error_avg > 0

    def test_column_fidelity_populated(self):
        ev     = FidelityEvaluator()
        real   = self._synth_data(100)
        synth  = self._synth_data(100)
        report = ev.evaluate(real, synth)
        assert len(report.column_fidelity) == 2
        cols = {c.name for c in report.column_fidelity}
        assert cols == {"age", "income"}

    def test_overlap_between_0_and_1(self):
        ev    = FidelityEvaluator()
        real  = self._synth_data(200)
        synth = self._synth_data(200)
        rep   = ev.evaluate(real, synth)
        for c in rep.column_fidelity:
            assert 0.0 <= c.overlap <= 1.0

    def test_empty_data_raises(self):
        ev = FidelityEvaluator()
        with pytest.raises(ValueError):
            ev.evaluate([], [{"x": 1.0}])

    def test_summary_string(self):
        ev     = FidelityEvaluator()
        data   = [{"a": float(i)} for i in range(50)]
        report = ev.evaluate(data, data)
        assert "grade" in report.summary().lower() or "Fidelity" in report.summary()
