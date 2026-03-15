"""
tests/test_training_anomaly.py  —  Training anomaly detection tests
AI Fortress · Chapter 4 · Code Sample 4.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import math
import numpy as np
import pytest
from loss_spike_detector import LossSpikeDetector
from gradient_norm_monitor import GradientNormMonitor
from lr_schedule_auditor import LRScheduleAuditor, cosine_decay_schedule, warmup_then_decay_schedule
from checkpoint_integrity import CheckpointIntegrityManager, CheckpointTamperError
from telemetry_aggregator import TelemetryAggregator


class TestLossSpikeDetector:
    def _feed_normal(self, det, n=30, mean=1.0, std=0.05, seed=0):
        rng = np.random.default_rng(seed)
        for i, loss in enumerate(rng.normal(mean, std, n)):
            det.observe(i, float(loss))

    def test_no_anomaly_stable_loss(self):
        det = LossSpikeDetector(window=20, z_threshold=3.5, min_window=10)
        self._feed_normal(det, n=50)
        assert det.summary()["total_anomalies"] == 0

    def test_detects_spike(self):
        det = LossSpikeDetector(window=20, z_threshold=3.0, min_window=10)
        self._feed_normal(det, n=25)
        result = det.observe(step=25, loss=100.0)   # massive spike
        assert result is not None
        assert result.severity in ("warning", "critical")

    def test_nan_detected_immediately(self):
        det = LossSpikeDetector()
        result = det.observe(step=0, loss=float("nan"))
        assert result is not None
        assert result.method == "nan_inf"
        assert result.severity == "critical"

    def test_inf_detected_immediately(self):
        det = LossSpikeDetector()
        result = det.observe(step=0, loss=float("inf"))
        assert result is not None
        assert result.method == "nan_inf"

    def test_iqr_detection(self):
        det = LossSpikeDetector(window=30, z_threshold=100, iqr_k=2.0, min_window=15)
        # Feed tight distribution
        for i in range(20):
            det.observe(i, 1.0 + (i % 2) * 0.01)
        # Inject outlier that passes Z but fails IQR
        result = det.observe(step=20, loss=5.0)
        assert result is not None


class TestGradientNormMonitor:
    def _feed_stable(self, mon, n=20, norm=1.0, group="encoder"):
        for i in range(n):
            mon.observe(i, {group: norm + np.random.default_rng(i).normal(0, 0.01)})

    def test_no_anomaly_stable_gradients(self):
        mon = GradientNormMonitor(window=20, min_window=10)
        self._feed_stable(mon, n=30)
        assert mon.summary()["total_anomalies"] == 0

    def test_detects_exploding_gradient(self):
        mon = GradientNormMonitor(window=20, explode_ratio=5.0, min_window=10)
        self._feed_stable(mon, n=15)
        anomalies = mon.observe(step=15, norms={"encoder": 1000.0})
        assert len(anomalies) > 0
        assert anomalies[0].severity in ("warning", "critical")

    def test_detects_nan_gradient(self):
        mon = GradientNormMonitor()
        anomalies = mon.observe(step=0, norms={"decoder": float("nan")})
        assert len(anomalies) == 1
        assert anomalies[0].severity == "critical"

    def test_detects_vanishing_gradient(self):
        mon = GradientNormMonitor(window=20, vanish_threshold=1e-6, min_window=10)
        for i in range(15):
            mon.observe(i, {"head": 1.0})
        anomalies = mon.observe(step=15, norms={"head": 1e-10})
        assert len(anomalies) > 0


class TestLRScheduleAuditor:
    def test_cosine_schedule_no_anomaly(self):
        fn  = cosine_decay_schedule(initial_lr=1e-3, total_steps=1000)
        aud = LRScheduleAuditor(fn, tolerance=0.001)
        # Feed exact schedule values
        for step in range(0, 100, 10):
            result = aud.observe(step=step, actual_lr=fn(step))
            assert result is None

    def test_detects_lr_deviation(self):
        fn  = cosine_decay_schedule(initial_lr=1e-3, total_steps=1000)
        aud = LRScheduleAuditor(fn, tolerance=0.01, critical_tolerance=0.10)
        result = aud.observe(step=100, actual_lr=fn(100) * 2.0)   # 100% deviation
        assert result is not None
        assert result.severity == "critical"

    def test_warmup_schedule(self):
        fn = warmup_then_decay_schedule(peak_lr=1e-3, warmup_steps=100, total_steps=1000)
        # During warmup, LR should increase linearly
        assert fn(0) == pytest.approx(0.0, abs=1e-10)
        assert fn(50) == pytest.approx(5e-4, rel=0.01)
        assert fn(100) == pytest.approx(1e-3, rel=0.01)

    def test_audit_history(self):
        fn  = cosine_decay_schedule(initial_lr=1e-3, total_steps=1000)
        aud = LRScheduleAuditor(fn, tolerance=0.01)
        steps   = list(range(10))
        lrs     = [fn(s) for s in steps]
        lrs[5]  = fn(5) * 5.0   # inject deviation at step 5
        anomalies = aud.audit_history(steps, lrs)
        assert len(anomalies) == 1
        assert anomalies[0].step == 5


class TestCheckpointIntegrity:
    def test_register_and_verify(self, tmp_path):
        cp = tmp_path / "epoch_01.pt"
        cp.write_bytes(b"fake model weights " * 100)
        manifest = tmp_path / "manifest.json"

        mgr = CheckpointIntegrityManager(manifest)
        entry = mgr.register(cp, epoch=1)
        assert len(entry.sha256) == 64

        # Verify passes
        verified = mgr.verify(cp)
        assert verified.epoch == 1

    def test_tamper_detected(self, tmp_path):
        cp = tmp_path / "epoch_02.pt"
        cp.write_bytes(b"original weights " * 50)
        mgr = CheckpointIntegrityManager(tmp_path / "manifest.json")
        mgr.register(cp, epoch=2)

        # Tamper
        cp.write_bytes(b"backdoored weights" * 50)
        with pytest.raises(CheckpointTamperError, match="FAILED integrity check"):
            mgr.verify(cp)

    def test_unregistered_checkpoint_raises(self, tmp_path):
        cp  = tmp_path / "injected.pt"
        cp.write_bytes(b"injected checkpoint")
        mgr = CheckpointIntegrityManager(tmp_path / "manifest.json")
        with pytest.raises(CheckpointTamperError, match="NOT in the manifest"):
            mgr.verify(cp)

    def test_verify_all(self, tmp_path):
        cps = []
        mgr = CheckpointIntegrityManager(tmp_path / "manifest.json")
        for i in range(3):
            cp = tmp_path / f"epoch_{i:02d}.pt"
            cp.write_bytes(f"weights epoch {i}".encode() * 20)
            mgr.register(cp, epoch=i)
            cps.append(cp)
        verified = mgr.verify_all()
        assert len(verified) == 3


class TestTelemetryAggregator:
    def test_record_event(self):
        agg = TelemetryAggregator(job_id="test-job")
        ev  = agg.record("loss_spike", "critical", "Loss exploded", step=42)
        assert ev.job_id == "test-job"
        assert ev.source == "loss_spike"

    def test_summary_counts(self):
        agg = TelemetryAggregator(job_id="test-job")
        agg.record("loss_spike",    "critical", "spike")
        agg.record("gradient_norm", "warning",  "explode")
        agg.record("lr_schedule",   "warning",  "drift")
        s = agg.summary()
        assert s["critical"] == 1
        assert s["warnings"]  == 2

    def test_save_report(self, tmp_path):
        import json
        agg = TelemetryAggregator(job_id="test-job")
        agg.record("checkpoint", "info", "checkpoint saved", step=100)
        agg.save_report(tmp_path / "report.json")
        data = json.loads((tmp_path / "report.json").read_text())
        assert data["summary"]["total_events"] == 1

    def test_jsonl_output(self, tmp_path):
        log_path = tmp_path / "events.jsonl"
        agg = TelemetryAggregator(job_id="test-job", output_path=log_path)
        agg.record("loss_spike", "warning", "spike at step 5", step=5)
        agg.record("loss_spike", "warning", "spike at step 9", step=9)
        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 2
        import json
        assert json.loads(lines[0])["step"] == 5
