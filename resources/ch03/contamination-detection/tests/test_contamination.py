"""
tests/test_contamination.py  —  Contamination detection tests
AI Fortress · Chapter 3 · Code Sample 3.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import numpy as np
import pandas as pd
import pytest
from label_flip_detector import LabelFlipDetector
from distribution_shift import DistributionShiftDetector
from duplicate_detector import DuplicateDetector
from outlier_detector import OutlierDetector
from contamination_report import ContaminationReport


def _clean_df(n=500, seed=0):
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "f1":    rng.normal(0, 1, n),
        "f2":    rng.normal(5, 2, n),
        "label": rng.choice(["cat","dog"], n, p=[0.5, 0.5]),
    })


class TestLabelFlipDetector:
    def test_no_anomaly_balanced(self):
        df       = _clean_df()
        findings = LabelFlipDetector().detect(df, "label", {"cat": 0.5, "dog": 0.5})
        severities = {f.severity for f in findings}
        assert "critical" not in severities

    def test_detects_severe_imbalance(self):
        rng = np.random.default_rng(1)
        # Flip 80% of cats to dog → severe imbalance
        df  = pd.DataFrame({
            "label": ["cat"] * 100 + ["dog"] * 400,
            "f1": rng.normal(0,1,500),
        })
        findings = LabelFlipDetector(chi2_alpha=0.05).detect(
            df, "label", {"cat": 0.5, "dog": 0.5}
        )
        assert any(f.severity in ("warning","critical") for f in findings)

    def test_missing_label_col_raises(self):
        df = _clean_df()
        with pytest.raises(ValueError):
            LabelFlipDetector().detect(df, "nonexistent_col")


class TestDistributionShiftDetector:
    def test_no_shift_same_distribution(self):
        rng  = np.random.default_rng(0)
        ref  = pd.DataFrame({"f1": rng.normal(0,1,300), "f2": rng.normal(5,2,300)})
        cur  = pd.DataFrame({"f1": rng.normal(0,1,300), "f2": rng.normal(5,2,300)})
        findings = DistributionShiftDetector(min_samples=50).detect(ref, cur, ["f1","f2"])
        assert not any(f.severity == "critical" for f in findings)

    def test_detects_mean_shift(self):
        rng  = np.random.default_rng(0)
        ref  = pd.DataFrame({"f1": rng.normal(0, 1, 500)})
        cur  = pd.DataFrame({"f1": rng.normal(10, 1, 500)})  # large mean shift
        findings = DistributionShiftDetector(min_samples=50).detect(ref, cur, ["f1"])
        assert any(f.severity in ("warning","critical") for f in findings)

    def test_insufficient_samples_returns_info(self):
        ref = pd.DataFrame({"f1": [1,2,3]})
        cur = pd.DataFrame({"f1": [4,5,6]})
        findings = DistributionShiftDetector(min_samples=100).detect(ref, cur, ["f1"])
        assert all(f.severity == "info" for f in findings)


class TestDuplicateDetector:
    def test_detects_exact_duplicates(self):
        df = pd.DataFrame({"f1": [1.0,2.0,1.0,3.0], "f2": [4.0,5.0,4.0,6.0]})
        findings = DuplicateDetector().detect(df, ["f1","f2"])
        assert any("exact" in f.description.lower() for f in findings)

    def test_no_duplicates_clean(self):
        df = _clean_df(100)
        findings = DuplicateDetector(max_near_dup_ratio=0.5).detect(df, ["f1","f2"])
        # Clean data shouldn't have critical exact-dup finding
        exact_critical = [f for f in findings if "exact" in f.description.lower()
                          and f.severity == "critical"]
        assert len(exact_critical) == 0

    def test_conflicting_labels_on_duplicates(self):
        df = pd.DataFrame({
            "f1":    [1.0, 1.0, 2.0],
            "f2":    [4.0, 4.0, 5.0],
            "label": ["cat", "dog", "cat"],   # identical features, different labels
        })
        findings = DuplicateDetector().detect(df, ["f1","f2"], label_col="label")
        assert any("conflicting" in f.description.lower() for f in findings)


class TestOutlierDetector:
    def test_no_outliers_normal_data(self):
        rng = np.random.default_rng(0)
        df  = pd.DataFrame({"f1": rng.normal(0,1,300), "f2": rng.normal(5,2,300)})
        findings = OutlierDetector(contamination=0.01, max_outlier_ratio=0.99).detect(df)
        assert all(f.severity == "info" for f in findings)

    def test_detects_injected_outliers(self):
        rng = np.random.default_rng(0)
        clean   = pd.DataFrame({"f1": rng.normal(0,1,480), "f2": rng.normal(5,2,480)})
        poison  = pd.DataFrame({"f1": [1000.0]*20, "f2": [1000.0]*20})
        df = pd.concat([clean, poison], ignore_index=True)
        findings = OutlierDetector(z_threshold=3.0).detect(df, ["f1","f2"])
        assert any(f.severity in ("warning","critical") for f in findings)


class TestContaminationReport:
    def test_report_summary(self):
        report = ContaminationReport("ds-test")
        from label_flip_detector import LabelFinding
        report.add_findings([
            LabelFinding(severity="critical", description="Test critical"),
            LabelFinding(severity="warning",  description="Test warning"),
        ])
        assert len(report.critical()) == 1
        assert len(report.warnings()) == 1

    def test_report_save(self, tmp_path):
        import json
        report = ContaminationReport("ds-save")
        report.save(tmp_path / "report.json")
        data = json.loads((tmp_path / "report.json").read_text())
        assert data["dataset_id"] == "ds-save"
