"""
tests/test_monitoring.py
AI Fortress · Chapter 10 · Code Sample 10.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import time
import pytest
from pathlib import Path

from health_check import (
    HealthChecker, ModelLoadCheck, LatencyCheck,
    PredictionSanityCheck, DependencyCheck, ResourceCheck,
)
from metric_collector import MetricCollector
from slo_tracker import SLODefinition, SLOTracker
from anomaly_alerting import (
    AlertEvaluator, MetricPoint,
    ThresholdRule, RateOfChangeRule, AnomalyRule, CompositeRule,
)


# ── HealthChecker ─────────────────────────────────────────────────────────────

class TestHealthChecker:

    def _predict(self, x): return 0.75

    def test_all_ok(self):
        checker = HealthChecker("fraud-model", "2.0")
        checker.add(ModelLoadCheck(self._predict, "input", name="model_load"))
        checker.add(DependencyCheck(lambda: True, name="feature_store"))
        report = checker.run()
        assert report.overall == "OK"
        assert report.is_healthy()

    def test_critical_fail_unhealthy(self):
        checker = HealthChecker()
        checker.add(ModelLoadCheck(lambda x: (_ for _ in ()).throw(RuntimeError("Model missing")),
                                   "input", name="model_load", critical=True))
        report = checker.run()
        assert report.overall == "UNHEALTHY"
        assert not report.is_healthy()

    def test_non_critical_fail_degraded(self):
        checker = HealthChecker()
        checker.add(DependencyCheck(lambda: False, name="optional_cache", critical=False))
        report = checker.run()
        assert report.overall == "DEGRADED"

    def test_latency_warn(self):
        import time as _time
        def slow_predict(x):
            _time.sleep(0.06)
            return 0.5
        checker = HealthChecker()
        checker.add(LatencyCheck(slow_predict, "x", warn_ms=10, fail_ms=5000,
                                  n_warmup=0, critical=False))
        report = checker.run()
        # Latency > 10ms → WARN → DEGRADED
        assert report.overall == "DEGRADED"

    def test_prediction_sanity_out_of_bounds(self):
        checker = HealthChecker()
        checker.add(PredictionSanityCheck(lambda x: 1.5, "x",
                                          min_val=0.0, max_val=1.0,
                                          name="sanity", critical=True))
        report = checker.run()
        assert report.overall == "UNHEALTHY"

    def test_prediction_sanity_in_bounds(self):
        checker = HealthChecker()
        checker.add(PredictionSanityCheck(lambda x: 0.5, "x",
                                          min_val=0.0, max_val=1.0))
        report = checker.run()
        assert report.overall == "OK"

    def test_model_load_expected_output_match(self):
        checker = HealthChecker()
        checker.add(ModelLoadCheck(lambda x: 42, "x", expected_output=42))
        report = checker.run()
        assert report.overall == "OK"

    def test_model_load_expected_output_mismatch(self):
        checker = HealthChecker()
        checker.add(ModelLoadCheck(lambda x: 99, "x", expected_output=42, critical=True))
        report = checker.run()
        assert report.overall == "UNHEALTHY"

    def test_check_count_matches(self):
        checker = HealthChecker()
        for i in range(3):
            checker.add(DependencyCheck(lambda: True, name=f"dep_{i}"))
        report = checker.run()
        assert len(report.checks) == 3

    def test_latency_recorded_in_check_result(self):
        checker = HealthChecker()
        checker.add(ModelLoadCheck(self._predict, "x"))
        report = checker.run()
        assert report.checks[0].latency_ms >= 0.0

    def test_save_json(self, tmp_path):
        checker = HealthChecker("svc", "1.0")
        checker.add(DependencyCheck(lambda: True))
        report = checker.run()
        p = tmp_path / "health.json"
        report.save_json(p)
        data = json.loads(p.read_text())
        assert data["overall"] == "OK"

    def test_exception_in_check_captured(self):
        def bad_check():
            raise ValueError("Unexpected error")
        checker = HealthChecker()
        checker.add(DependencyCheck(bad_check, name="bad", critical=True))
        report = checker.run()
        assert report.overall == "UNHEALTHY"
        assert any("exception" in c.detail.lower() for c in report.checks)


# ── MetricCollector ───────────────────────────────────────────────────────────

class TestMetricCollector:

    def test_request_counter_increments(self):
        mc = MetricCollector("svc", "model")
        mc.record_request("success", 10.0)
        mc.record_request("error",   50.0)
        snap = mc.snapshot()
        assert snap["requests"]["success"] == 1
        assert snap["requests"]["error"]   == 1

    def test_error_rate_computed(self):
        mc = MetricCollector()
        for _ in range(9):
            mc.record_request("success")
        mc.record_request("error")
        snap = mc.snapshot()
        assert 0.09 <= snap["error_rate"] <= 0.11

    def test_latency_quantiles(self):
        mc = MetricCollector()
        for v in range(1, 101):
            mc.record_request("success", float(v))
        snap = mc.snapshot()
        assert snap["latency_p50"] == pytest.approx(50.5, abs=5)
        assert snap["latency_p99"] > snap["latency_p50"]

    def test_drift_score_set(self):
        mc = MetricCollector()
        mc.set_drift_score(75.0)
        assert mc.snapshot()["drift_score"] == 75.0

    def test_drift_score_clamped(self):
        mc = MetricCollector()
        mc.set_drift_score(150.0)
        assert mc.snapshot()["drift_score"] == 100.0

    def test_prediction_mean_std(self):
        mc = MetricCollector()
        for v in [0.1, 0.2, 0.3, 0.4, 0.5]:
            mc.record_prediction(v)
        snap = mc.snapshot()
        assert abs(snap["prediction_mean"] - 0.3) < 0.01

    def test_cert_expiry_recorded(self):
        mc = MetricCollector()
        mc.set_cert_expiry("model-server-cert", 14.0)
        assert mc.snapshot()["cert_days"]["model-server-cert"] == 14.0

    def test_prometheus_format_structure(self):
        mc = MetricCollector("fraud-svc", "fraud-v2")
        mc.record_request("success", 20.0)
        mc.set_drift_score(30.0)
        output = mc.expose()
        assert "ml_requests_total" in output
        assert "ml_drift_score"    in output
        assert "ml_latency_ms"     in output
        assert "fraud-svc"         in output

    def test_prometheus_format_parseable(self):
        mc = MetricCollector()
        mc.record_request("success", 15.0)
        output = mc.expose()
        # Each metric line should contain a space (label block + value)
        metric_lines = [l for l in output.splitlines()
                        if l and not l.startswith("#")]
        for line in metric_lines:
            assert " " in line

    def test_active_keys_gauge(self):
        mc = MetricCollector()
        mc.set_active_keys(42)
        assert mc.snapshot()["active_keys"] == 42


# ── SLOTracker ────────────────────────────────────────────────────────────────

class TestSLOTracker:

    def _slo(self, target=0.999):
        return SLODefinition(name="inference-availability", target=target,
                             window_days=30, service="fraud-model")

    def test_clean_traffic_ok(self):
        tracker = SLOTracker(self._slo())
        now     = time.time()
        tracker.record_batch(total=1000, errors=0, ts=now)
        status  = tracker.status(now=now)
        assert status.overall == "OK"
        assert status.long_burn_rate < 1.0

    def test_high_error_rate_critical(self):
        tracker = SLOTracker(self._slo(target=0.999))
        now     = time.time()
        # 10% error rate = 100× burn rate for 99.9% SLO
        tracker.record_batch(total=1000, errors=100, ts=now)
        status = tracker.status(now=now)
        assert status.overall == "CRITICAL"
        assert status.long_burn_rate >= 6.0

    def test_slow_burn_warning(self):
        tracker = SLOTracker(self._slo(target=0.999))
        now     = time.time()
        # 0.2% error rate = 2× burn rate (above 1×, below 6×)
        tracker.record_batch(total=10000, errors=20, ts=now)
        status = tracker.status(now=now)
        assert status.overall in ("WARNING", "CRITICAL")

    def test_budget_consumed_pct(self):
        tracker = SLOTracker(self._slo(target=0.999))
        now     = time.time()
        tracker.record_batch(total=1000, errors=1, ts=now)
        status  = tracker.status(now=now)
        assert 0 <= status.budget_consumed_pct <= 100

    def test_no_events_ok(self):
        tracker = SLOTracker(self._slo())
        status  = tracker.status()
        assert status.overall == "OK"
        assert status.long_burn_rate == 0.0

    def test_burn_rate_alert_detail_populated(self):
        tracker = SLOTracker(self._slo(target=0.999))
        now     = time.time()
        tracker.record_batch(total=100, errors=10, ts=now)
        status  = tracker.status(now=now)
        if status.alerts:
            assert len(status.alerts[0].detail) > 10

    def test_save_json(self, tmp_path):
        tracker = SLOTracker(self._slo())
        tracker.record_batch(total=1000, errors=0)
        status  = tracker.status()
        p       = tmp_path / "slo.json"
        status.save_json(p)
        data = json.loads(p.read_text())
        assert "slo_name" in data
        assert "long_burn_rate" in data

    def test_individual_record(self):
        tracker = SLOTracker(self._slo())
        now     = time.time()
        for _ in range(99):
            tracker.record(is_error=False, ts=now)
        tracker.record(is_error=True, ts=now)
        status = tracker.status(now=now)
        assert status.total_requests_long == 100


# ── AlertEvaluator ────────────────────────────────────────────────────────────

class TestAlertEvaluator:

    def _point(self, name: str, value: float) -> MetricPoint:
        return MetricPoint(ts=time.time(), name=name, value=value)

    def test_threshold_above_fires(self):
        rule  = ThresholdRule("high_error", "ml_error_rate", threshold=0.05, direction="above")
        ev    = AlertEvaluator([rule])
        fired = ev.evaluate(self._point("ml_error_rate", 0.10))
        assert len(fired) == 1
        assert fired[0].rule_name == "high_error"
        assert fired[0].severity == "WARNING"

    def test_threshold_below_no_fire(self):
        rule  = ThresholdRule("high_error", "ml_error_rate", threshold=0.05)
        ev    = AlertEvaluator([rule])
        fired = ev.evaluate(self._point("ml_error_rate", 0.02))
        assert len(fired) == 0

    def test_threshold_below_direction(self):
        rule  = ThresholdRule("low_keys", "ml_active_keys", threshold=5, direction="below",
                               severity="CRITICAL")
        ev    = AlertEvaluator([rule])
        fired = ev.evaluate(self._point("ml_active_keys", 3))
        assert len(fired) == 1
        assert fired[0].severity == "CRITICAL"

    def test_rate_of_change_fires(self):
        rule  = RateOfChangeRule("latency_spike", "ml_latency_p99", pct_change=50)
        ev    = AlertEvaluator([rule])
        ev.evaluate(self._point("ml_latency_p99", 100.0))
        fired = ev.evaluate(self._point("ml_latency_p99", 200.0))  # 100% change
        assert len(fired) == 1

    def test_rate_of_change_no_fire_small_change(self):
        rule  = RateOfChangeRule("latency_spike", "ml_latency_p99", pct_change=50)
        ev    = AlertEvaluator([rule])
        ev.evaluate(self._point("ml_latency_p99", 100.0))
        fired = ev.evaluate(self._point("ml_latency_p99", 105.0))  # 5% change
        assert len(fired) == 0

    def test_anomaly_rule_fires_on_spike(self):
        rule = AnomalyRule("drift_spike", "ml_drift_score", z_threshold=2.0,
                           window_size=20, min_samples=5)
        ev   = AlertEvaluator([rule])
        # Feed stable values
        for _ in range(15):
            ev.evaluate(self._point("ml_drift_score", 10.0))
        # Feed a large spike
        fired = ev.evaluate(self._point("ml_drift_score", 100.0))
        assert len(fired) == 1
        assert "z-score" in fired[0].detail

    def test_anomaly_rule_no_fire_below_min_samples(self):
        rule  = AnomalyRule("drift_spike", "ml_drift_score", min_samples=10)
        ev    = AlertEvaluator([rule])
        for _ in range(5):
            ev.evaluate(self._point("ml_drift_score", 10.0))
        fired = ev.evaluate(self._point("ml_drift_score", 1000.0))
        assert len(fired) == 0

    def test_composite_rule_requires_all_children(self):
        r1   = ThresholdRule("err",     "ml_error_rate",   threshold=0.05)
        r2   = ThresholdRule("drift",   "ml_drift_score",  threshold=50.0)
        comp = CompositeRule("combined_alert", rules=[r1, r2], severity="CRITICAL")
        ev   = AlertEvaluator([comp])
        # Only one metric passes both thresholds
        fired = ev.evaluate(self._point("ml_error_rate", 0.10))   # r1 fires but r2 can't fire (wrong metric)
        # CompositeRule fires only if BOTH fire on same point — should not fire here
        assert len(fired) == 0

    def test_multiple_rules_multiple_firings(self):
        r1  = ThresholdRule("r1", "ml_error_rate", threshold=0.01)
        r2  = ThresholdRule("r2", "ml_error_rate", threshold=0.005)
        ev  = AlertEvaluator([r1, r2])
        fired = ev.evaluate(self._point("ml_error_rate", 0.05))
        assert len(fired) == 2

    def test_wrong_metric_not_fired(self):
        rule  = ThresholdRule("high_error", "ml_error_rate", threshold=0.05)
        ev    = AlertEvaluator([rule])
        fired = ev.evaluate(self._point("ml_drift_score", 99.0))
        assert len(fired) == 0

    def test_alert_written_to_file(self, tmp_path):
        log   = tmp_path / "alerts.jsonl"
        rule  = ThresholdRule("high_err", "ml_error_rate", threshold=0.01)
        ev    = AlertEvaluator([rule], alert_path=log)
        ev.evaluate(self._point("ml_error_rate", 0.10))
        lines = log.read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["rule_name"] == "high_err"

    def test_fired_alerts_history(self):
        rule = ThresholdRule("test", "metric_a", threshold=1.0)
        ev   = AlertEvaluator([rule])
        for v in [2.0, 0.5, 3.0, 0.1]:
            ev.evaluate(self._point("metric_a", v))
        history = ev.fired_alerts()
        assert len(history) == 2   # only 2.0 and 3.0 exceed threshold

    def test_snapshot_evaluation(self):
        r1  = ThresholdRule("high_err",   "error_rate",  threshold=0.05)
        r2  = ThresholdRule("high_drift", "drift_score", threshold=60.0)
        ev  = AlertEvaluator([r1, r2])
        fired = ev.evaluate_snapshot({"error_rate": 0.10, "drift_score": 70.0})
        assert len(fired) == 2
