"""
tests/test_dp_sgd.py
AI Fortress · Chapter 13 · Code Sample 13.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, math, pytest
from pathlib import Path

from privacy_engine_wrapper import DPConfig, PrivacyEngineWrapper
from privacy_budget_tracker import PrivacyBudgetTracker, BudgetExhaustedError
from gradient_clipper import clip_gradient, clip_and_aggregate, add_gaussian_noise, l2_norm
from privacy_accountant import RDPAccountant


# ── DPConfig ──────────────────────────────────────────────────────────────────

class TestDPConfig:

    def test_valid_config(self):
        cfg = DPConfig(noise_multiplier=1.1, max_grad_norm=1.0,
                       sample_rate=0.01, target_epsilon=8.0, target_delta=1e-5)
        cfg.validate()   # should not raise

    def test_bad_sample_rate_raises(self):
        cfg = DPConfig(1.1, 1.0, 1.5, 8.0, 1e-5)   # sample_rate > 1
        with pytest.raises(ValueError, match="sample_rate"):
            cfg.validate()

    def test_negative_noise_multiplier_raises(self):
        cfg = DPConfig(-0.5, 1.0, 0.01, 8.0, 1e-5)
        with pytest.raises(ValueError, match="noise_multiplier"):
            cfg.validate()

    def test_delta_out_of_range_raises(self):
        cfg = DPConfig(1.1, 1.0, 0.01, 8.0, 1.5)
        with pytest.raises(ValueError, match="delta"):
            cfg.validate()


# ── PrivacyEngineWrapper ──────────────────────────────────────────────────────

class TestPrivacyEngineWrapper:

    def _wrapper(self, **kw):
        cfg = DPConfig(noise_multiplier=1.1, max_grad_norm=1.0,
                       sample_rate=0.01, target_epsilon=8.0, target_delta=1e-5,
                       **kw)
        return PrivacyEngineWrapper(cfg)

    def test_step_accountant_increments(self):
        w   = self._wrapper()
        e1  = w.step_accountant()
        e2  = w.step_accountant()
        assert e2 >= e1
        assert w.state.steps_taken == 2

    def test_end_epoch_increments(self):
        w = self._wrapper()
        w.end_epoch()
        assert w.state.epochs_completed == 1

    def test_detach_sets_flag(self):
        w = self._wrapper()
        w.detach()
        assert not w.state.attached

    def test_attach_without_opacus_raises(self):
        w = self._wrapper()
        with pytest.raises(ImportError, match="opacus"):
            w.attach(object(), object(), object())

    def test_audit_log_written(self, tmp_path):
        log = tmp_path / "dp.jsonl"
        cfg = DPConfig(1.1, 1.0, 0.01, 8.0, 1e-5)
        w   = PrivacyEngineWrapper(cfg, audit_path=log)
        w.step_accountant()
        w.end_epoch()
        w.detach()
        events = {json.loads(l)["event"] for l in log.read_text().splitlines() if l}
        assert "epoch_completed" in events
        assert "engine_detached" in events


# ── PrivacyBudgetTracker ──────────────────────────────────────────────────────

class TestPrivacyBudgetTracker:

    def test_register_and_spend(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("model-a", max_epsilon=8.0, delta=1e-5)
        status  = tracker.spend("model-a", epsilon_increment=1.0)
        assert abs(status.epsilon_spent - 1.0) < 1e-9

    def test_cumulative_spending(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("m", max_epsilon=10.0, delta=1e-5)
        for _ in range(5):
            tracker.spend("m", 1.0)
        assert abs(tracker.status("m").epsilon_spent - 5.0) < 1e-9

    def test_budget_exhausted_raises(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("m", max_epsilon=2.0, delta=1e-5)
        tracker.spend("m", 1.5)
        with pytest.raises(BudgetExhaustedError):
            tracker.spend("m", 1.0)

    def test_budget_exhausted_no_raise_when_flag_false(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("m", max_epsilon=1.0, delta=1e-5)
        status  = tracker.spend("m", 2.0, raise_on_exceed=False)
        assert status.exhausted

    def test_near_exhausted_flag(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("m", max_epsilon=10.0, delta=1e-5, warn_fraction=0.80)
        tracker.spend("m", 8.5, raise_on_exceed=False)
        assert tracker.status("m").near_exhausted

    def test_reset_clears_history(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("m", max_epsilon=10.0, delta=1e-5)
        tracker.spend("m", 5.0)
        tracker.reset("m")
        assert tracker.status("m").epsilon_spent == 0.0

    def test_unregistered_model_raises(self):
        tracker = PrivacyBudgetTracker()
        with pytest.raises(KeyError):
            tracker.spend("ghost", 1.0)

    def test_all_statuses(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("a", 8.0, 1e-5)
        tracker.register("b", 4.0, 1e-5)
        statuses = tracker.all_statuses()
        assert len(statuses) == 2

    def test_pct_consumed(self):
        tracker = PrivacyBudgetTracker()
        tracker.register("m", max_epsilon=10.0, delta=1e-5)
        tracker.spend("m", 4.0)
        assert abs(tracker.status("m").pct_consumed - 40.0) < 0.01

    def test_audit_log(self, tmp_path):
        log     = tmp_path / "budget.jsonl"
        tracker = PrivacyBudgetTracker(audit_path=log)
        tracker.register("m", max_epsilon=10.0, delta=1e-5)
        tracker.spend("m", 1.0)
        events  = {json.loads(l)["event"] for l in log.read_text().splitlines() if l}
        assert "budget_registered" in events


# ── gradient_clipper ──────────────────────────────────────────────────────────

class TestGradientClipper:

    def test_l2_norm(self):
        assert abs(l2_norm([3.0, 4.0]) - 5.0) < 1e-9

    def test_clip_gradient_below_threshold(self):
        g, norm = clip_gradient([1.0, 0.0], max_norm=5.0)
        assert abs(l2_norm(g) - 1.0) < 1e-9

    def test_clip_gradient_above_threshold(self):
        g, norm = clip_gradient([3.0, 4.0], max_norm=2.0)
        assert l2_norm(g) <= 2.0 + 1e-9

    def test_clip_and_aggregate_all_below(self):
        grads = [[1.0, 0.0], [0.0, 1.0], [0.5, 0.5]]
        mean, stats = clip_and_aggregate(grads, max_grad_norm=5.0)
        assert stats.n_clipped == 0
        assert abs(mean[0] - (1.0 + 0.0 + 0.5) / 3) < 1e-9

    def test_clip_and_aggregate_clips_large(self):
        grads = [[10.0, 0.0], [0.0, 0.0]]
        mean, stats = clip_and_aggregate(grads, max_grad_norm=1.0)
        assert stats.n_clipped == 1
        assert stats.clip_fraction == 0.5

    def test_clip_fraction(self):
        grads = [[100.0], [0.1], [100.0], [0.1]]
        _, stats = clip_and_aggregate(grads, max_grad_norm=1.0)
        assert stats.n_clipped == 2
        assert abs(stats.clip_fraction - 0.5) < 1e-9

    def test_mismatched_dim_raises(self):
        with pytest.raises(ValueError, match="dimension"):
            clip_and_aggregate([[1.0, 2.0], [1.0]], max_grad_norm=1.0)

    def test_empty_gradients_raises(self):
        with pytest.raises(ValueError, match="empty"):
            clip_and_aggregate([], max_grad_norm=1.0)

    def test_add_gaussian_noise_changes_gradient(self):
        import random
        random.seed(42)
        g    = [1.0, 1.0, 1.0]
        noisy = add_gaussian_noise(g, noise_multiplier=1.0, max_grad_norm=1.0, n_samples=100)
        assert noisy != g

    def test_clipped_norm_le_max(self):
        for _ in range(20):
            import random
            grad = [random.gauss(0, 10) for _ in range(5)]
            clipped, _ = clip_gradient(grad, max_norm=1.0)
            assert l2_norm(clipped) <= 1.0 + 1e-9


# ── RDPAccountant ─────────────────────────────────────────────────────────────

class TestRDPAccountant:

    def test_zero_steps_zero_epsilon(self):
        acc = RDPAccountant(noise_multiplier=1.1, sample_rate=0.01, delta=1e-5)
        # Before composing, epsilon should be very small or near 0
        eps = acc.get_epsilon()
        assert eps >= 0

    def test_epsilon_increases_with_steps(self):
        acc = RDPAccountant(noise_multiplier=1.1, sample_rate=0.01, delta=1e-5)
        acc.compose(100)
        eps_100 = acc.get_epsilon()
        acc.compose(100)
        eps_200 = acc.get_epsilon()
        assert eps_200 > eps_100

    def test_more_noise_less_epsilon(self):
        acc_low  = RDPAccountant(noise_multiplier=0.5, sample_rate=0.01, delta=1e-5)
        acc_high = RDPAccountant(noise_multiplier=2.0, sample_rate=0.01, delta=1e-5)
        acc_low.compose(100)
        acc_high.compose(100)
        assert acc_high.get_epsilon() < acc_low.get_epsilon()

    def test_steps_to_budget_returns_positive(self):
        acc = RDPAccountant(noise_multiplier=1.1, sample_rate=0.01, delta=1e-5)
        acc.compose(50)
        remaining = acc.steps_to_budget(target_epsilon=10.0)
        assert remaining >= 0

    def test_steps_to_budget_zero_when_exceeded(self):
        acc = RDPAccountant(noise_multiplier=0.1, sample_rate=0.5, delta=1e-5)
        acc.compose(1000)
        assert acc.steps_to_budget(target_epsilon=1.0) == 0

    def test_state_records_steps(self):
        acc = RDPAccountant(noise_multiplier=1.1, sample_rate=0.01, delta=1e-5)
        acc.compose(42)
        assert acc.state().steps == 42

    def test_higher_delta_lower_epsilon(self):
        acc = RDPAccountant(noise_multiplier=1.1, sample_rate=0.01, delta=1e-5)
        acc.compose(100)
        eps_tight = acc.get_epsilon_at_delta(1e-8)
        eps_loose = acc.get_epsilon_at_delta(1e-3)
        assert eps_loose < eps_tight
