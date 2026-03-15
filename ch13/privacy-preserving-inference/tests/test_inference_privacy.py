"""
tests/test_inference_privacy.py
AI Fortress · Chapter 13 · Code Sample 13.E
Run: pytest tests/ -v
"""
from __future__ import annotations
import math, pytest, random
from output_perturbation import OutputPerturbation
from confidence_suppressor import ConfidenceSuppressor
from kanonymity_checker import KAnonymityChecker


# ── OutputPerturbation ────────────────────────────────────────────────────────

class TestOutputPerturbation:

    def test_laplace_changes_output(self):
        p = OutputPerturbation(1.0, mechanism="laplace", seed=1)
        r = p.perturb([0.8, 0.2])
        assert r.perturbed != r.original

    def test_gaussian_changes_output(self):
        p = OutputPerturbation(1.0, delta=1e-5, mechanism="gaussian", seed=2)
        r = p.perturb([0.8, 0.2])
        assert r.perturbed != r.original

    def test_scale_inverse_epsilon(self):
        p_small = OutputPerturbation(0.1, mechanism="laplace")
        p_large = OutputPerturbation(10.0, mechanism="laplace")
        assert p_small._scale > p_large._scale

    def test_invalid_epsilon_raises(self):
        with pytest.raises(ValueError, match="epsilon"):
            OutputPerturbation(-1.0)

    def test_batch_perturb(self):
        p       = OutputPerturbation(1.0, seed=42)
        batch   = [[0.9, 0.1], [0.6, 0.4], [0.5, 0.5]]
        results = p.perturb_batch(batch)
        assert len(results) == 3

    def test_mechanism_recorded(self):
        p = OutputPerturbation(1.0, mechanism="gaussian", delta=1e-5)
        r = p.perturb([0.7, 0.3])
        assert r.mechanism == "gaussian"

    def test_noise_scale_stored(self):
        p = OutputPerturbation(2.0, sensitivity=1.0, mechanism="laplace")
        assert abs(p._scale - 0.5) < 1e-9   # 1.0 / 2.0

    def test_higher_epsilon_smaller_noise_on_average(self):
        random.seed(0)
        p_priv   = OutputPerturbation(0.1, mechanism="laplace", seed=5)
        p_util   = OutputPerturbation(10.0, mechanism="laplace", seed=5)
        out      = [0.8]
        n        = 500
        err_priv = sum(abs(p_priv.perturb(out).perturbed[0] - out[0]) for _ in range(n)) / n
        err_util = sum(abs(p_util.perturb(out).perturbed[0] - out[0]) for _ in range(n)) / n
        assert err_priv > err_util


# ── ConfidenceSuppressor ──────────────────────────────────────────────────────

class TestConfidenceSuppressor:

    def test_caps_high_confidence(self):
        sup = ConfidenceSuppressor(max_confidence=0.9, suppression_level="none")
        r   = sup.suppress(0.99, predicted_class=1)
        assert r.suppressed_confidence <= 0.9
        assert r.was_capped

    def test_below_cap_not_capped(self):
        sup = ConfidenceSuppressor(max_confidence=0.95)
        r   = sup.suppress(0.7, predicted_class=0)
        assert not r.was_capped

    def test_coarse_quantisation(self):
        sup = ConfidenceSuppressor(suppression_level="coarse")
        r   = sup.suppress(0.73, predicted_class=0)
        # Coarse = 5 bins → multiples of 0.2
        assert r.suppressed_confidence in [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]

    def test_medium_quantisation(self):
        sup = ConfidenceSuppressor(suppression_level="medium")
        r   = sup.suppress(0.85, predicted_class=1)
        # Medium = 10 bins → multiples of 0.1
        assert round(r.suppressed_confidence * 10) == round(r.suppressed_confidence * 10)

    def test_no_suppression(self):
        sup = ConfidenceSuppressor(max_confidence=1.0, suppression_level="none")
        r   = sup.suppress(0.75, predicted_class=0)
        assert not r.was_quantised
        assert r.suppressed_confidence == 0.75

    def test_batch_suppress(self):
        sup     = ConfidenceSuppressor()
        results = sup.suppress_batch([0.9, 0.7, 0.5], [0, 1, 2])
        assert len(results) == 3

    def test_batch_length_mismatch_raises(self):
        sup = ConfidenceSuppressor()
        with pytest.raises(ValueError):
            sup.suppress_batch([0.9, 0.7], [0])

    def test_invalid_max_confidence_raises(self):
        with pytest.raises(ValueError):
            ConfidenceSuppressor(max_confidence=1.5)

    def test_information_loss_pct(self):
        sup = ConfidenceSuppressor(suppression_level="coarse")
        assert sup.information_loss_pct() > 0


# ── KAnonymityChecker ─────────────────────────────────────────────────────────

def _ref_data():
    return [
        {"age_group": "25-34", "gender": "M", "region": "EU"},
        {"age_group": "25-34", "gender": "M", "region": "EU"},
        {"age_group": "25-34", "gender": "M", "region": "EU"},
        {"age_group": "25-34", "gender": "M", "region": "EU"},
        {"age_group": "25-34", "gender": "M", "region": "EU"},   # k=5 for this QI
        {"age_group": "55-64", "gender": "F", "region": "US"},   # k=1 (unique)
    ]


class TestKAnonymityChecker:

    def _checker(self, k=3):
        return KAnonymityChecker(
            k=k, quasi_id_cols=["age_group", "gender"],
            reference_data=_ref_data()
        )

    def test_satisfies_k_anon(self):
        checker = self._checker(k=3)
        result  = checker.check({"age_group": "25-34", "gender": "M"}, predicted_class=1)
        assert result.satisfies_k_anon
        assert result.k_value == 5

    def test_fails_k_anon_unique(self):
        checker = self._checker(k=3)
        result  = checker.check({"age_group": "55-64", "gender": "F"}, predicted_class=0)
        assert not result.satisfies_k_anon
        assert result.suppressed

    def test_suppressed_class_is_minus_one(self):
        checker = self._checker(k=3)
        result  = checker.check({"age_group": "55-64", "gender": "F"}, predicted_class=0)
        assert result.predicted_class == -1

    def test_k_one_always_satisfies(self):
        checker = KAnonymityChecker(
            k=1, quasi_id_cols=["age_group"],
            reference_data=[{"age_group": "rare-group"}],
        )
        result = checker.check({"age_group": "rare-group"}, 0)
        assert result.satisfies_k_anon

    def test_unknown_qi_value_fails(self):
        checker = self._checker(k=3)
        result  = checker.check({"age_group": "unknown", "gender": "X"}, 0)
        assert not result.satisfies_k_anon
        assert result.k_value == 0

    def test_equivalence_class_size(self):
        checker = self._checker()
        size    = checker.equivalence_class_size({"age_group": "25-34", "gender": "M"})
        assert size == 5

    def test_invalid_k_raises(self):
        with pytest.raises(ValueError):
            KAnonymityChecker(k=0, quasi_id_cols=["age"], reference_data=[])

    def test_generalise_mode(self):
        checker = KAnonymityChecker(
            k=3, quasi_id_cols=["age_group"],
            reference_data=[{"age_group": "rare"}],
            suppress_below_k=False,
        )
        result = checker.check({"age_group": "rare"}, 1)
        assert result.generalised
        assert not result.suppressed
