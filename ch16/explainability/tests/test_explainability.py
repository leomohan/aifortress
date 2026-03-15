"""
tests/test_explainability.py
AI Fortress · Chapter 16 · Code Sample 16.E
Run: pytest tests/ -v
"""
from __future__ import annotations
import random, pytest
from shap_approximator import SHAPApproximator
from counterfactual_generator import CounterfactualGenerator
from explanation_auditor import ExplanationAuditor


# Simple linear model: output = 0.2*x0 + 0.5*x1 + 0.3*x2
def _model(x):
    return min(1.0, max(0.0, 0.2 * x[0] + 0.5 * x[1] + 0.3 * x[2]))

_NAMES  = ["income", "credit_score", "debt_ratio"]
_RANGES = {"income": (0.0, 1.0), "credit_score": (0.0, 1.0), "debt_ratio": (0.0, 1.0)}

def _ref_data(n=50, seed=0):
    random.seed(seed)
    return [[random.uniform(0, 1) for _ in range(3)] for _ in range(n)]


# ── SHAPApproximator ──────────────────────────────────────────────────────────

class TestSHAPApproximator:

    def _explainer(self):
        return SHAPApproximator(_model, _ref_data(), _NAMES, n_samples=50)

    def test_returns_explanation(self):
        expl = self._explainer().explain([0.8, 0.9, 0.1])
        assert set(expl.shap_values.keys()) == set(_NAMES)

    def test_predicted_value_matches_model(self):
        inst = [0.7, 0.8, 0.3]
        expl = self._explainer().explain(inst)
        assert abs(expl.predicted_value - _model(inst)) < 0.01

    def test_top_features_sorted_by_magnitude(self):
        expl   = self._explainer().explain([0.5, 0.9, 0.1])
        mags   = [abs(v) for _, v in expl.top_features]
        assert mags == sorted(mags, reverse=True)

    def test_high_credit_score_positive_shap(self):
        # credit_score has coefficient 0.5 — high value should be positive SHAP
        expl = self._explainer().explain([0.5, 1.0, 0.1])
        assert expl.shap_values["credit_score"] > 0

    def test_summary_string(self):
        expl = self._explainer().explain([0.5, 0.5, 0.5])
        s    = expl.summary()
        assert "Prediction" in s

    def test_base_value_is_mean_output(self):
        ref   = _ref_data()
        expl  = SHAPApproximator(_model, ref, _NAMES).explain([0.5] * 3)
        expected_base = sum(_model(r) for r in ref) / len(ref)
        assert abs(expl.base_value - expected_base) < 0.01

    def test_all_features_present(self):
        expl = self._explainer().explain([0.1, 0.2, 0.3])
        assert len(expl.shap_values) == 3


# ── CounterfactualGenerator ───────────────────────────────────────────────────

class TestCounterfactualGenerator:

    def _gen(self, immutable=None):
        return CounterfactualGenerator(
            _model, _NAMES, _RANGES,
            immutable_features=immutable,
            step_size=0.05, max_iterations=300,
        )

    def test_finds_counterfactual(self):
        cf = self._gen().generate([0.1, 0.1, 0.1], target_pred=0.5)
        assert cf.found

    def test_cf_pred_meets_target(self):
        cf = self._gen().generate([0.1, 0.1, 0.1], target_pred=0.5)
        assert cf.cf_pred >= 0.5

    def test_original_pred_recorded(self):
        inst = [0.1, 0.1, 0.1]
        cf   = self._gen().generate(inst)
        assert abs(cf.original_pred - _model(inst)) < 0.01

    def test_already_meets_target_trivial(self):
        cf = self._gen().generate([0.9, 0.9, 0.9], target_pred=0.5)
        assert cf.found
        assert cf.n_changes == 0

    def test_immutable_feature_unchanged(self):
        cf = self._gen(immutable={"income"}).generate([0.1, 0.1, 0.1], target_pred=0.5)
        if cf.found:
            assert "income" not in cf.changed_features

    def test_n_changes_matches_changed_features(self):
        cf = self._gen().generate([0.1, 0.1, 0.1], target_pred=0.5)
        assert cf.n_changes == len(cf.changed_features)

    def test_impossible_target_not_found(self):
        # Constant zero model can never reach target 0.9
        def zero_model(x): return 0.0
        gen = CounterfactualGenerator(zero_model, _NAMES, _RANGES, max_iterations=10)
        cf  = gen.generate([0.5, 0.5, 0.5], target_pred=0.9)
        assert not cf.found


# ── ExplanationAuditor ────────────────────────────────────────────────────────

class TestExplanationAuditor:

    def _explanations(self, n=10, seed=1):
        random.seed(seed)
        ref   = _ref_data(30, seed)
        expl  = SHAPApproximator(_model, ref, _NAMES, n_samples=30)
        return [expl.explain([random.uniform(0, 1) for _ in range(3)]) for _ in range(n)]

    def test_pass_on_good_explanations(self):
        auditor = ExplanationAuditor(completeness_tol=0.5, consistency_thr=0.5)
        result  = auditor.audit(self._explanations())
        assert result.overall_grade in ("PASS", "CONDITIONAL")

    def test_completeness_checked(self):
        auditor = ExplanationAuditor(completeness_tol=0.001)  # very tight
        result  = auditor.audit(self._explanations())
        assert isinstance(result.completeness_ok, bool)

    def test_sensitivity_ok_nonzero_shap(self):
        auditor = ExplanationAuditor()
        result  = auditor.audit(self._explanations())
        assert result.sensitivity_ok  # linear model always produces nonzero SHAP

    def test_sensitivity_fails_all_zero(self):
        from shap_approximator import SHAPExplanation
        zero_ex = SHAPExplanation(
            instance=[0.5]*3, feature_names=_NAMES,
            shap_values={n: 0.0 for n in _NAMES},
            base_value=0.5, predicted_value=0.5,
            top_features=[(n, 0.0) for n in _NAMES],
        )
        auditor = ExplanationAuditor()
        result  = auditor.audit([zero_ex])
        assert not result.sensitivity_ok

    def test_fairness_gap_computed_with_groups(self):
        exps   = self._explanations(10)
        groups = ["A"] * 5 + ["B"] * 5
        result = ExplanationAuditor().audit(exps, groups=groups)
        assert result.fairness_gap >= 0

    def test_grade_populated(self):
        result = ExplanationAuditor().audit(self._explanations())
        assert result.overall_grade in ("PASS", "CONDITIONAL", "FAIL")

    def test_violations_list(self):
        result = ExplanationAuditor().audit(self._explanations())
        assert isinstance(result.violations, list)
