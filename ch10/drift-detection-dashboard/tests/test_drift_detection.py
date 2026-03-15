"""
tests/test_drift_detection.py
AI Fortress · Chapter 10 · Code Sample 10.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import numpy as np
import pytest
from pathlib import Path

from feature_drift_detector import FeatureDriftDetector, _psi
from prediction_drift_monitor import PredictionDriftMonitor
from feature_importance_drift import FeatureImportanceDrift
from drift_report import DriftReportBuilder


rng = np.random.default_rng(42)


# ── FeatureDriftDetector ──────────────────────────────────────────────────────

class TestFeatureDriftDetector:

    def test_no_drift_continuous(self):
        ref = {"age": rng.normal(35, 10, 1000).tolist()}
        cur = {"age": rng.normal(35, 10, 500).tolist()}
        rep = FeatureDriftDetector().detect(ref, cur)
        assert rep.results[0].status == "OK"

    def test_critical_drift_continuous(self):
        ref = {"score": rng.normal(0.5, 0.05, 1000).tolist()}
        cur = {"score": rng.normal(0.9, 0.05, 500).tolist()}   # big shift
        rep = FeatureDriftDetector().detect(ref, cur)
        assert rep.results[0].status in ("WARNING", "CRITICAL")

    def test_categorical_no_drift(self):
        cats = ["A", "B", "C"]
        ref  = {"country": rng.choice(cats, 1000, p=[0.5, 0.3, 0.2]).tolist()}
        cur  = {"country": rng.choice(cats, 500,  p=[0.5, 0.3, 0.2]).tolist()}
        rep  = FeatureDriftDetector().detect(ref, cur, dtypes={"country": "categorical"})
        assert rep.results[0].status == "OK"

    def test_categorical_new_category_flagged(self):
        ref = {"country": ["A", "B", "A", "B", "A", "B", "A", "B", "A", "B"]}
        cur = {"country": ["A", "B", "A", "B", "A", "B", "A", "B", "C", "C"]}
        rep = FeatureDriftDetector().detect(ref, cur, dtypes={"country": "categorical"})
        assert rep.results[0].status in ("WARNING", "CRITICAL")
        assert "C" in rep.results[0].new_categories

    def test_overall_pass_on_clean(self):
        ref = {"x": rng.normal(0, 1, 500).tolist()}
        cur = {"x": rng.normal(0, 1, 500).tolist()}
        rep = FeatureDriftDetector().detect(ref, cur)
        assert rep.overall_pass

    def test_overall_fail_on_critical(self):
        ref = {"x": rng.normal(0,  1, 1000).tolist()}
        cur = {"x": rng.normal(10, 1, 500).tolist()}
        rep = FeatureDriftDetector().detect(ref, cur)
        assert not rep.overall_pass
        assert rep.critical > 0

    def test_multiple_features(self):
        ref = {"a": rng.normal(0,1,500).tolist(), "b": rng.normal(5,1,500).tolist()}
        cur = {"a": rng.normal(0,1,500).tolist(), "b": rng.normal(5,1,500).tolist()}
        rep = FeatureDriftDetector().detect(ref, cur)
        assert rep.total_features == 2

    def test_missing_feature_skipped(self):
        ref = {"a": rng.normal(0,1,500).tolist(), "b": rng.normal(0,1,500).tolist()}
        cur = {"a": rng.normal(0,1,500).tolist()}
        rep = FeatureDriftDetector().detect(ref, cur)
        assert rep.total_features == 1

    def test_psi_zero_same_distribution(self):
        data = rng.normal(0, 1, 1000)
        assert _psi(data, data) < 0.01

    def test_psi_high_different_distribution(self):
        ref = rng.normal(0,  1, 2000)
        cur = rng.normal(10, 1, 2000)
        assert _psi(ref, cur) > 0.25

    def test_save_json(self, tmp_path):
        ref = {"x": rng.normal(0,1,200).tolist()}
        cur = {"x": rng.normal(0,1,200).tolist()}
        rep = FeatureDriftDetector().detect(ref, cur)
        p   = tmp_path / "drift.json"
        rep.save_json(p)
        data = json.loads(p.read_text())
        assert "results" in data

    def test_small_sample_handled(self):
        ref = {"x": [1.0, 2.0, 3.0]}   # only 3 samples
        cur = {"x": [4.0, 5.0, 6.0]}
        rep = FeatureDriftDetector().detect(ref, cur)
        assert rep.results[0].status == "OK"  # insufficient samples


# ── PredictionDriftMonitor ────────────────────────────────────────────────────

class TestPredictionDriftMonitor:

    def test_no_drift_classification(self):
        base = rng.beta(2, 5, 1000)
        cur  = rng.beta(2, 5, 500)
        mon  = PredictionDriftMonitor(task="classification")
        res  = mon.check(base, cur)
        assert res.status == "OK"

    def test_critical_drift_classification(self):
        base = rng.beta(2, 8, 1000)
        cur  = rng.beta(8, 2, 500)   # distribution reversed
        mon  = PredictionDriftMonitor(task="classification")
        res  = mon.check(base, cur)
        assert res.status in ("WARNING", "CRITICAL")

    def test_jsd_computed(self):
        base = rng.normal(0, 1, 500)
        cur  = rng.normal(5, 1, 500)
        mon  = PredictionDriftMonitor()
        res  = mon.check(base, cur)
        assert res.jsd > 0

    def test_mean_shift_recorded(self):
        base = rng.normal(0, 1, 500)
        cur  = rng.normal(3, 1, 500)
        mon  = PredictionDriftMonitor()
        res  = mon.check(base, cur)
        assert abs(res.mean_shift - 3.0) < 0.5

    def test_regression_no_drift(self):
        base = rng.normal(100, 10, 1000)
        cur  = rng.normal(100, 10, 500)
        mon  = PredictionDriftMonitor(task="regression")
        res  = mon.check(base, cur)
        assert res.status == "OK"

    def test_insufficient_samples_ok(self):
        mon = PredictionDriftMonitor()
        res = mon.check([0.5, 0.6], [0.4])
        assert res.status == "OK"


# ── FeatureImportanceDrift ────────────────────────────────────────────────────

class TestFeatureImportanceDrift:

    def _base(self):
        return {"f1": 0.30, "f2": 0.25, "f3": 0.20, "f4": 0.15, "f5": 0.10}

    def test_identical_importances_ok(self):
        imp = FeatureImportanceDrift()
        res = imp.check(self._base(), self._base())
        assert res.status == "OK"
        assert res.spearman_corr == pytest.approx(1.0, abs=0.01)

    def test_minor_shifts_ok(self):
        base = self._base()
        curr = {"f1": 0.29, "f2": 0.26, "f3": 0.21, "f4": 0.14, "f5": 0.10}
        imp  = FeatureImportanceDrift()
        res  = imp.check(base, curr)
        assert res.status == "OK"

    def test_rank_inversion_detected(self):
        base = {"f1": 0.4, "f2": 0.3, "f3": 0.2, "f4": 0.1}
        curr = {"f4": 0.4, "f3": 0.3, "f2": 0.2, "f1": 0.1}  # fully reversed
        imp  = FeatureImportanceDrift(top_k=4)
        res  = imp.check(base, curr)
        assert res.status in ("WARNING", "CRITICAL")

    def test_importance_collapse_critical(self):
        base = {"f1": 0.5, "f2": 0.3, "f3": 0.2}
        curr = {"f1": 0.001, "f2": 0.6, "f3": 0.399}  # f1 collapsed
        imp  = FeatureImportanceDrift(collapse_thresh=0.1)
        res  = imp.check(base, curr)
        assert any(s.signal == "importance_collapse" for s in res.signals)
        assert res.status in ("WARNING", "CRITICAL")

    def test_new_top_feature_detected(self):
        base = {"f1": 0.4, "f2": 0.3, "f3": 0.2, "f4": 0.1}
        curr = {"f1": 0.1, "f2": 0.1, "f3": 0.1, "f4": 0.7}  # f4 rockets up
        imp  = FeatureImportanceDrift(top_k=2)
        res  = imp.check(base, curr)
        assert any(s.signal == "new_top_feature" for s in res.signals)

    def test_top_k_overlap_full(self):
        imp = FeatureImportanceDrift(top_k=3)
        res = imp.check(self._base(), self._base())
        assert res.top_k_overlap == pytest.approx(1.0)

    def test_save_json(self, tmp_path):
        imp = FeatureImportanceDrift()
        res = imp.check(self._base(), self._base())
        p   = tmp_path / "imp.json"
        res.save_json(p)
        data = json.loads(p.read_text())
        assert "spearman_corr" in data


# ── DriftReportBuilder ────────────────────────────────────────────────────────

class TestDriftReportBuilder:

    def _clean_inputs(self):
        """Return clean (OK) drift results for all three detectors."""
        ref = {"x": rng.normal(0,1,500).tolist()}
        cur = {"x": rng.normal(0,1,500).tolist()}
        fd  = FeatureDriftDetector().detect(ref, cur)
        pd  = PredictionDriftMonitor().check(
            rng.beta(2,5,500), rng.beta(2,5,500))
        imp_base = {"f1": 0.5, "f2": 0.3, "f3": 0.2}
        id_ = FeatureImportanceDrift().check(imp_base, imp_base)
        return fd, pd, id_

    def test_clean_report_passes(self):
        fd, pd, id_ = self._clean_inputs()
        builder     = DriftReportBuilder(fail_threshold=50)
        report      = builder.build("fraud-model", "2.0.0", fd, pd, id_)
        assert report.overall_pass
        assert report.overall_status == "OK"

    def test_critical_drift_fails_gate(self):
        ref = {"x": rng.normal(0,  1, 1000).tolist()}
        cur = {"x": rng.normal(10, 1, 500).tolist()}
        fd  = FeatureDriftDetector().detect(ref, cur)
        pd  = PredictionDriftMonitor().check(
            rng.beta(2,5,500), rng.beta(2,5,500))
        imp_base = {"f1": 0.5, "f2": 0.3, "f3": 0.2}
        id_ = FeatureImportanceDrift().check(imp_base, imp_base)
        builder = DriftReportBuilder(fail_threshold=50)
        report  = builder.build("fraud-model", "2.0.0", fd, pd, id_)
        assert not report.overall_pass
        assert report.overall_status == "CRITICAL"

    def test_recommendations_populated(self):
        fd, pd, id_ = self._clean_inputs()
        report      = DriftReportBuilder().build("m", "1.0", fd, pd, id_)
        assert len(report.recommendations) > 0

    def test_save_json(self, tmp_path):
        fd, pd, id_ = self._clean_inputs()
        report      = DriftReportBuilder().build("m", "1.0", fd, pd, id_)
        p           = tmp_path / "report.json"
        report.save_json(p)
        data = json.loads(p.read_text())
        assert "overall_score"    in data
        assert "feature_drift"    in data
        assert "prediction_drift" in data
        assert "importance_drift" in data

    def test_summary_string(self):
        fd, pd, id_ = self._clean_inputs()
        report      = DriftReportBuilder().build("fraud-model", "2.0.0", fd, pd, id_)
        assert "fraud-model" in report.summary()
        assert "2.0.0"       in report.summary()

    def test_report_has_timestamp_and_id(self):
        fd, pd, id_ = self._clean_inputs()
        report      = DriftReportBuilder().build("m", "1.0", fd, pd, id_)
        assert report.report_id
        assert report.timestamp
