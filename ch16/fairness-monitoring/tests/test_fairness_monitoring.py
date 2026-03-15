"""
tests/test_fairness_monitoring.py
AI Fortress · Chapter 16 · Code Sample 16.D
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest, random
from parity_tracker import ParityTracker
from alert_engine import FairnessAlertEngine
from dashboard_builder import DashboardBuilder


def _window(n=200, dpd_target=0.05, seed=1):
    random.seed(seed)
    groups = (["A"] * (n // 2)) + (["B"] * (n // 2))
    # A gets higher positive rate by dpd_target
    y_pred = (
        [1 if random.random() < 0.5 + dpd_target else 0 for _ in range(n // 2)] +
        [1 if random.random() < 0.5 else 0 for _ in range(n // 2)]
    )
    return y_pred, groups


# ── ParityTracker ─────────────────────────────────────────────────────────────

class TestParityTracker:

    def test_record_observation(self):
        tracker = ParityTracker(window_size=100)
        yp, g   = _window(200)
        obs     = tracker.record(yp, g)
        assert obs.dpd >= 0

    def test_breach_detected(self):
        tracker = ParityTracker(dpd_threshold=0.02, window_size=100)
        yp, g   = _window(200, dpd_target=0.20)
        obs     = tracker.record(yp, g)
        assert obs.breached

    def test_no_breach_under_threshold(self):
        tracker = ParityTracker(dpd_threshold=0.30, window_size=100)
        yp, g   = _window(200, dpd_target=0.05)
        obs     = tracker.record(yp, g)
        assert not obs.breached

    def test_min_window_size_enforced(self):
        tracker = ParityTracker(window_size=500)
        yp, g   = _window(100)
        with pytest.raises(ValueError, match="min"):
            tracker.record(yp, g)

    def test_trend_returns_none_for_one_window(self):
        tracker = ParityTracker(window_size=100)
        yp, g   = _window(200)
        tracker.record(yp, g)
        assert tracker.trend() is None

    def test_trend_degrading(self):
        tracker = ParityTracker(dpd_threshold=0.30, window_size=100)
        tracker.record(*_window(200, dpd_target=0.01, seed=1))
        tracker.record(*_window(200, dpd_target=0.20, seed=2))
        trend = tracker.trend()
        assert trend is not None
        assert trend.direction == "degrading"

    def test_breached_windows_filtered(self):
        tracker = ParityTracker(dpd_threshold=0.05, window_size=100)
        tracker.record(*_window(200, dpd_target=0.20, seed=1))
        tracker.record(*_window(200, dpd_target=0.01, seed=2))
        breached = tracker.breached_windows()
        assert len(breached) == 1

    def test_history_appended(self):
        tracker = ParityTracker(window_size=100)
        for i in range(3):
            tracker.record(*_window(200, seed=i))
        assert len(tracker.history()) == 3

    def test_persist_to_jsonl(self, tmp_path):
        p       = tmp_path / "parity.jsonl"
        tracker = ParityTracker(window_size=100, history_path=p)
        tracker.record(*_window(200))
        lines   = p.read_text().strip().splitlines()
        assert len(lines) == 1


# ── FairnessAlertEngine ───────────────────────────────────────────────────────

class TestFairnessAlertEngine:

    def _obs(self, dpd, thr=0.10):
        from parity_tracker import ParityObservation
        return ParityObservation(
            window_id="w1", timestamp="2026-01-01T00:00:00Z",
            n_samples=200, group_rates={"A": 0.6, "B": 0.6 - dpd},
            dpd=dpd, threshold=thr, breached=(dpd > thr),
        )

    def test_no_alert_below_warn(self):
        engine = FairnessAlertEngine(warn_fraction=0.80)
        alert  = engine.evaluate(self._obs(0.05, thr=0.10))
        assert alert is None

    def test_warning_near_threshold(self):
        engine = FairnessAlertEngine(warn_fraction=0.80)
        alert  = engine.evaluate(self._obs(0.085, thr=0.10))
        assert alert is not None
        assert alert.severity == "WARNING"

    def test_alert_at_threshold(self):
        engine = FairnessAlertEngine()
        alert  = engine.evaluate(self._obs(0.12, thr=0.10))
        assert alert.severity == "ALERT"

    def test_critical_at_2x_threshold(self):
        engine = FairnessAlertEngine()
        alert  = engine.evaluate(self._obs(0.25, thr=0.10))
        assert alert.severity == "CRITICAL"

    def test_acknowledge_clears_open(self):
        engine = FairnessAlertEngine()
        alert  = engine.evaluate(self._obs(0.12))
        engine.acknowledge(alert.alert_id)
        assert len(engine.open_alerts()) == 0

    def test_acknowledge_unknown_raises(self):
        engine = FairnessAlertEngine()
        with pytest.raises(KeyError):
            engine.acknowledge("ghost")

    def test_alert_log_written(self, tmp_path):
        log    = tmp_path / "alerts.jsonl"
        engine = FairnessAlertEngine(log_path=log)
        engine.evaluate(self._obs(0.15))
        data   = json.loads(log.read_text().splitlines()[0])
        assert "severity" in data


# ── DashboardBuilder ──────────────────────────────────────────────────────────

class TestDashboardBuilder:

    def _setup(self):
        tracker = ParityTracker(dpd_threshold=0.10, window_size=100)
        engine  = FairnessAlertEngine()
        for i in range(3):
            obs = tracker.record(*_window(200, dpd_target=0.05 + i * 0.05, seed=i))
            engine.evaluate(obs, tracker.trend())
        return tracker, engine

    def test_build_dashboard(self):
        tracker, engine = self._setup()
        data = DashboardBuilder().build("fraud", tracker, engine)
        assert data.n_windows == 3

    def test_dpd_series_length(self):
        tracker, engine = self._setup()
        data = DashboardBuilder().build("m", tracker, engine)
        assert len(data.dpd_series) == 3

    def test_save_json(self, tmp_path):
        tracker, engine = self._setup()
        data = DashboardBuilder().build("m", tracker, engine)
        p    = tmp_path / "dashboard.json"
        data.save_json(p)
        obj  = json.loads(p.read_text())
        assert "latest_dpd" in obj
