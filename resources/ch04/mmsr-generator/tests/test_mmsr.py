"""
tests/test_mmsr.py  —  MMSR generator tests
AI Fortress · Chapter 4 · Code Sample 4.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from training_config import TrainingConfig
from compute_provenance import ComputeProvenance
from data_lineage import DataLineage
from security_controls import SecurityControlsEvidence, CHAPTER4_CONTROLS
from mmsr_report import MMSRReport


def _make_config(**overrides):
    defaults = dict(
        model_name       = "fraud-detector",
        model_version    = "v3.0",
        task_type        = "classification",
        framework        = "pytorch",
        framework_version = "2.2.0",
        architecture     = "ResNet-18",
        epochs           = 100,
        batch_size       = 256,
        learning_rate    = 1e-3,
        optimizer        = "AdamW",
        loss_function    = "CrossEntropyLoss",
        random_seed      = 42,
        gradient_clipping = 1.0,
    )
    defaults.update(overrides)
    return TrainingConfig(**defaults)


def _make_lineage():
    return DataLineage(
        dataset_id          = "customers-v3",
        dataset_version     = "2024-Q4",
        dataset_sha256      = "a" * 64,
        preprocessing_steps = ["normalise", "anonymise", "split"],
        split_ratios        = {"train": 0.70, "val": 0.15, "test": 0.15},
        n_train             = 70000,
        n_val               = 15000,
        n_test              = 15000,
        anonymisation_applied = True,
        gdpr_lawful_basis   = "legitimate_interests",
    )


def _make_controls(all_active: bool = True):
    ctrl = SecurityControlsEvidence(job_id="test-job-001")
    for c in CHAPTER4_CONTROLS:
        ctrl.attest(c, active=all_active, evidence_ref=f"ref-{c}")
    return ctrl


class TestTrainingConfig:
    def test_security_gaps_with_no_seed(self):
        cfg = _make_config(random_seed=None, gradient_clipping=None)
        gaps = cfg.security_gaps()
        assert any("random_seed" in g for g in gaps)
        assert any("gradient_clipping" in g for g in gaps)

    def test_no_gaps_when_fully_configured(self):
        cfg = _make_config()
        assert len(cfg.security_gaps()) == 0

    def test_python_version_auto_populated(self):
        cfg = _make_config()
        assert cfg.python_version != ""
        assert "." in cfg.python_version


class TestComputeProvenance:
    def test_capture(self):
        prv = ComputeProvenance.capture(job_id="test-job")
        assert prv.job_id    == "test-job"
        assert prv.hostname  != ""
        assert prv.started_at != ""

    def test_complete(self):
        prv = ComputeProvenance.capture()
        prv.complete()
        assert prv.completed_at != ""

    def test_to_dict(self):
        prv = ComputeProvenance.capture()
        d   = prv.to_dict()
        assert "job_id" in d
        assert "network_isolated" in d


class TestDataLineage:
    def test_to_dict(self):
        lin = _make_lineage()
        d   = lin.to_dict()
        assert d["dataset_id"] == "customers-v3"
        assert d["anonymisation_applied"] is True


class TestSecurityControls:
    def test_coverage_all_active(self):
        ctrl = _make_controls(all_active=True)
        assert ctrl.coverage_score() == pytest.approx(1.0)

    def test_coverage_none_active(self):
        ctrl = SecurityControlsEvidence("job-x")
        for c in CHAPTER4_CONTROLS:
            ctrl.attest(c, active=False)
        assert ctrl.coverage_score() == pytest.approx(0.0)

    def test_unattest_returns_missing(self):
        ctrl = SecurityControlsEvidence("job-y")
        ctrl.attest("secrets_manager", active=True)
        missing = ctrl.unattest()
        assert "secrets_manager" not in missing
        assert "checkpoint_integrity" in missing


class TestMMSRReport:
    def test_build_produces_sha256(self):
        report = MMSRReport.build(
            _make_config(),
            ComputeProvenance.capture(),
            _make_lineage(),
            _make_controls(),
        )
        assert len(report.sha256) == 64

    def test_tamper_detection(self):
        report = MMSRReport.build(
            _make_config(),
            ComputeProvenance.capture(),
            _make_lineage(),
            _make_controls(),
        )
        original_sha = report.sha256
        # Tamper with the report
        report.config["model_name"] = "evil-model"
        # SHA-256 no longer matches payload
        import hashlib
        payload = json.dumps(
            {k: v for k, v in report.__dict__.items() if k != "sha256"}, sort_keys=True
        )
        new_sha = hashlib.sha256(payload.encode()).hexdigest()
        assert new_sha != original_sha   # tampering invalidates hash

    def test_save_json(self, tmp_path):
        report = MMSRReport.build(
            _make_config(),
            ComputeProvenance.capture(),
            _make_lineage(),
            _make_controls(),
        )
        path = tmp_path / "mmsr.json"
        report.save_json(path)
        data = json.loads(path.read_text())
        assert data["config"]["model_name"] == "fraud-detector"
        assert len(data["sha256"]) == 64

    def test_save_markdown(self, tmp_path):
        report = MMSRReport.build(
            _make_config(),
            ComputeProvenance.capture(),
            _make_lineage(),
            _make_controls(),
        )
        path = tmp_path / "mmsr.md"
        report.save_markdown(path)
        md = path.read_text()
        assert "# Model and ML System Report" in md
        assert "fraud-detector" in md
        assert "Security Controls" in md
        assert "100%" in md   # full coverage

    def test_partial_coverage_shows_gaps(self, tmp_path):
        ctrl = SecurityControlsEvidence("job-partial")
        ctrl.attest("secrets_manager", active=True)
        # Most controls unattested
        report = MMSRReport.build(
            _make_config(),
            ComputeProvenance.capture(),
            _make_lineage(),
            ctrl,
        )
        assert report.coverage_score < 0.5
        assert len(report.unattested) > 5
        md = report.save_markdown(tmp_path / "partial.md") or (tmp_path / "partial.md").read_text()
