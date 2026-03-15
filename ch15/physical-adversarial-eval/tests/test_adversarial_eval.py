"""
tests/test_adversarial_eval.py
AI Fortress · Chapter 15 · Code Sample 15.E
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest, random
from patch_robustness_tester import PatchRobustnessTester, PatchAttackConfig
from env_distortion_simulator import EnvironmentalDistortionSimulator, DistortionConfig
from robustness_reporter import RobustnessReporter


# Helpers: perfect model, random model, data
def _input_fn(i):
    random.seed(i)
    return [random.gauss(0, 1) for _ in range(20)]

def _label_fn(i):
    return i % 3

def _perfect_model(x):
    # Model that always returns the "right" label based on deterministic feature
    return int(abs(x[0]) * 3) % 3

def _random_model(x):
    return random.randint(0, 2)

def _thresh_model(x):
    # Correct on clean (positive first element), fails on patched (negative patch values)
    return 0 if x[0] > 0 else 1


# ── PatchRobustnessTester ─────────────────────────────────────────────────────

class TestPatchRobustnessTester:

    def test_returns_result(self):
        tester = PatchRobustnessTester(_thresh_model, _label_fn, _input_fn)
        result = tester.evaluate(PatchAttackConfig(n_trials=20))
        assert 0.0 <= result.clean_accuracy  <= 1.0
        assert 0.0 <= result.patched_accuracy <= 1.0

    def test_accuracy_drop_computed(self):
        tester = PatchRobustnessTester(_thresh_model, _label_fn, _input_fn)
        result = tester.evaluate(PatchAttackConfig(n_trials=30))
        assert abs(result.accuracy_drop - (result.clean_accuracy - result.patched_accuracy)) < 1e-6

    def test_high_patch_fraction_more_damage(self):
        tester = PatchRobustnessTester(_thresh_model, _label_fn, _input_fn)
        r_low  = tester.evaluate(PatchAttackConfig(patch_fraction=0.01, n_trials=50, patch_value=-10.0))
        r_high = tester.evaluate(PatchAttackConfig(patch_fraction=0.90, n_trials=50, patch_value=-10.0))
        assert r_high.accuracy_drop >= r_low.accuracy_drop

    def test_severity_returned(self):
        tester  = PatchRobustnessTester(_random_model, _label_fn, _input_fn)
        result  = tester.evaluate(PatchAttackConfig(n_trials=20))
        assert result.severity in ("critical", "high", "moderate", "low")

    def test_n_trials_recorded(self):
        tester = PatchRobustnessTester(_thresh_model, _label_fn, _input_fn)
        result = tester.evaluate(PatchAttackConfig(n_trials=15))
        assert result.n_trials == 15

    def test_asr_is_one_minus_patched_acc(self):
        tester = PatchRobustnessTester(_thresh_model, _label_fn, _input_fn)
        result = tester.evaluate(PatchAttackConfig(n_trials=20))
        assert abs(result.attack_success_rate - (1.0 - result.patched_accuracy)) < 1e-6


# ── EnvironmentalDistortionSimulator ──────────────────────────────────────────

class TestEnvironmentalDistortionSimulator:

    def _sim(self):
        return EnvironmentalDistortionSimulator(_thresh_model, _label_fn, _input_fn)

    def test_gaussian_noise(self):
        sim    = self._sim()
        result = sim.evaluate([DistortionConfig("gaussian", 0.1)], n_trials=30)
        assert len(result) == 1
        assert result[0].distortion_type == "gaussian"

    def test_multiple_distortions(self):
        sim     = self._sim()
        configs = [
            DistortionConfig("gaussian",  0.1),
            DistortionConfig("dropout",   0.2),
            DistortionConfig("clip",      0.3),
            DistortionConfig("quantise",  0.5),
            DistortionConfig("blur",      0.5),
        ]
        results = sim.evaluate(configs, n_trials=20)
        assert len(results) == 5

    def test_high_severity_reduces_accuracy(self):
        sim  = self._sim()
        r_lo = sim.evaluate([DistortionConfig("dropout", 0.01)], n_trials=50)
        r_hi = sim.evaluate([DistortionConfig("dropout", 0.99)], n_trials=50)
        assert r_hi[0].distorted_accuracy <= r_lo[0].distorted_accuracy

    def test_accuracy_drop_field(self):
        sim    = self._sim()
        result = sim.evaluate([DistortionConfig("gaussian", 0.5)], n_trials=20)
        r = result[0]
        assert abs(r.accuracy_drop - (r.clean_accuracy - r.distorted_accuracy)) < 1e-6


# ── RobustnessReporter ────────────────────────────────────────────────────────

class TestRobustnessReporter:

    def _patch(self, drop=0.05):
        from patch_robustness_tester import PatchRobustnessResult
        return PatchRobustnessResult(
            clean_accuracy=0.90, patched_accuracy=0.90-drop,
            accuracy_drop=drop, attack_success_rate=0.10+drop,
            n_trials=100, patch_fraction=0.1,
            severity="low" if drop < 0.05 else "moderate" if drop < 0.15 else "high",
            recommendation="Acceptable." if drop < 0.05 else "Apply adversarial training.",
        )

    def _dist(self, drop=0.05):
        from env_distortion_simulator import DistortionEvalResult
        return [DistortionEvalResult("gaussian", 0.1, 0.9, 0.9-drop, drop, 50)]

    def test_pass_grade(self):
        rep    = RobustnessReporter()
        report = rep.generate("fraud", "1.0", self._patch(drop=0.02))
        assert report.overall_grade == "PASS"

    def test_fail_grade_high_drop(self):
        rep    = RobustnessReporter()
        report = rep.generate("fraud", "1.0", self._patch(drop=0.35))
        assert report.overall_grade == "FAIL"

    def test_conditional_grade(self):
        rep    = RobustnessReporter()
        report = rep.generate("fraud", "1.0", self._patch(drop=0.15))
        assert report.overall_grade in ("CONDITIONAL", "FAIL")

    def test_worst_drop_max(self):
        rep    = RobustnessReporter()
        report = rep.generate("m", "1.0",
                              patch_result=self._patch(0.10),
                              distortion_results=self._dist(0.25))
        assert abs(report.worst_drop - 0.25) < 0.01

    def test_save_json(self, tmp_path):
        rep    = RobustnessReporter()
        report = rep.generate("m", "1.0", self._patch())
        p      = tmp_path / "robustness.json"
        report.save_json(p)
        data   = json.loads(p.read_text())
        assert "overall_grade" in data

    def test_summary_string(self):
        rep    = RobustnessReporter()
        report = rep.generate("fraud", "2.0", self._patch())
        assert "fraud" in report.summary()

    def test_report_id_unique(self):
        rep = RobustnessReporter()
        r1  = rep.generate("m", "1.0")
        r2  = rep.generate("m", "1.0")
        assert r1.report_id != r2.report_id
