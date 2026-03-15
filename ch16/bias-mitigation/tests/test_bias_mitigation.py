"""
tests/test_bias_mitigation.py
AI Fortress · Chapter 16 · Code Sample 16.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import random, pytest
from reweighing import Reweighing
from threshold_optimizer import ThresholdOptimizer
from adversarial_debiasing_stub import AdversarialDebiasingConfig, AdversarialDebiasingTrainer


def _data(n=200, seed=7):
    random.seed(seed)
    groups = (["A"] * (n // 2)) + (["B"] * (n // 2))
    labels = [random.randint(0, 1) for _ in range(n)]
    scores = [random.uniform(0, 1) for _ in range(n)]
    return groups, labels, scores


# ── Reweighing ────────────────────────────────────────────────────────────────

class TestReweighing:

    def test_returns_result(self):
        groups, labels, _ = _data()
        result = Reweighing().fit_transform(groups, labels)
        assert len(result.weights) == len(groups)

    def test_weights_positive(self):
        groups, labels, _ = _data()
        result = Reweighing().fit_transform(groups, labels)
        assert all(w > 0 for w in result.weights)

    def test_weight_range_stored(self):
        groups, labels, _ = _data()
        result = Reweighing().fit_transform(groups, labels)
        mn, mx = result.weight_range
        assert mn <= mx

    def test_n_groups_correct(self):
        groups, labels, _ = _data()
        result = Reweighing().fit_transform(groups, labels)
        assert result.n_groups == 2

    def test_mismatched_lengths_raise(self):
        with pytest.raises(ValueError):
            Reweighing().fit_transform(["A", "B"], [0])

    def test_weights_near_one_for_balanced_data(self):
        """If groups and labels are perfectly balanced, weights should be ≈ 1."""
        groups = ["A", "A", "B", "B"] * 25
        labels = [0, 1, 0, 1] * 25
        result = Reweighing().fit_transform(groups, labels)
        for w in result.weights:
            assert abs(w - 1.0) < 0.05

    def test_gl_weights_all_keys_present(self):
        groups = ["A", "A", "B", "B"]
        labels = [0, 1, 0, 1]
        result = Reweighing().fit_transform(groups, labels)
        assert "(A,0)" in result.group_label_weights
        assert "(B,1)" in result.group_label_weights


# ── ThresholdOptimizer ────────────────────────────────────────────────────────

class TestThresholdOptimizer:

    def _scores(self, n=200, seed=3):
        random.seed(seed)
        y_true = [random.randint(0, 1) for _ in range(n)]
        scores = [random.uniform(0, 1) for _ in range(n)]
        groups = (["A"] * (n // 2)) + (["B"] * (n // 2))
        return y_true, scores, groups

    def test_returns_result(self):
        yt, sc, g = self._scores()
        opt    = ThresholdOptimizer()
        result = opt.optimize(yt, sc, g)
        assert result.thresholds

    def test_threshold_per_group(self):
        yt, sc, g = self._scores()
        opt    = ThresholdOptimizer()
        result = opt.optimize(yt, sc, g)
        assert "A" in result.thresholds
        assert "B" in result.thresholds

    def test_thresholds_in_0_1(self):
        yt, sc, g = self._scores()
        result = ThresholdOptimizer().optimize(yt, sc, g)
        for t in result.thresholds.values():
            assert 0.0 <= t <= 1.0

    def test_residual_dpd_nonneg(self):
        yt, sc, g = self._scores()
        result = ThresholdOptimizer().optimize(yt, sc, g)
        assert result.residual_dpd >= 0

    def test_equal_opportunity_target(self):
        yt, sc, g = self._scores()
        result = ThresholdOptimizer(target_metric="equal_opportunity").optimize(yt, sc, g)
        assert result.target_metric == "equal_opportunity"

    def test_mismatched_lengths_raise(self):
        opt = ThresholdOptimizer()
        with pytest.raises(ValueError):
            opt.optimize([0, 1], [0.5], ["A", "B"])

    def test_accuracy_overall_in_range(self):
        yt, sc, g = self._scores()
        result = ThresholdOptimizer().optimize(yt, sc, g)
        assert 0.0 <= result.accuracy_overall <= 1.0


# ── AdversarialDebiasingTrainer ───────────────────────────────────────────────

class TestAdversarialDebiasing:

    def test_train_returns_result(self):
        cfg     = AdversarialDebiasingConfig()
        trainer = AdversarialDebiasingTrainer(cfg)
        result  = trainer.train([[1, 0], [0, 1]] * 50, [1, 0] * 50, ["A", "B"] * 50)
        assert result.final_epoch > 0

    def test_higher_weight_lower_dpd(self):
        cfg_low  = AdversarialDebiasingConfig(adversary_loss_weight=0.1, max_epochs=10)
        cfg_high = AdversarialDebiasingConfig(adversary_loss_weight=0.9, max_epochs=10)
        r_low  = AdversarialDebiasingTrainer(cfg_low).train([], [0, 1] * 50, ["A", "B"] * 50)
        r_high = AdversarialDebiasingTrainer(cfg_high).train([], [0, 1] * 50, ["A", "B"] * 50)
        assert r_high.estimated_dpd <= r_low.estimated_dpd

    def test_training_history_populated(self):
        cfg    = AdversarialDebiasingConfig(max_epochs=5)
        result = AdversarialDebiasingTrainer(cfg).train([], [0, 1] * 50, ["A", "B"] * 50)
        assert len(result.training_history) > 0

    def test_invalid_weight_raises(self):
        with pytest.raises(ValueError):
            AdversarialDebiasingConfig(adversary_loss_weight=1.5).validate()

    def test_invalid_lr_raises(self):
        with pytest.raises(ValueError):
            AdversarialDebiasingConfig(learning_rate=-0.1).validate()

    def test_task_loss_positive(self):
        cfg    = AdversarialDebiasingConfig()
        result = AdversarialDebiasingTrainer(cfg).train([], [1] * 50, ["A"] * 50)
        assert result.task_loss > 0
