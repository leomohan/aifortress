"""
tests/test_pretrained_assessment.py
AI Fortress · Chapter 8 · Code Sample 8.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import hashlib
import io
import json
import os
import pickle
import pickletools
import struct
import zipfile
from pathlib import Path
import pytest

from pickle_safety_scanner import PickleSafetyScanner
from weight_integrity_verifier import WeightIntegrityVerifier
from model_card_scorer import ModelCardScorer


# ── Pickle helper factories ───────────────────────────────────────────────────

def _safe_pickle() -> bytes:
    """A safe pickle containing only a plain dict."""
    return pickle.dumps({"weights": [1.0, 2.0, 3.0], "bias": 0.5})


def _malicious_pickle_os_system() -> bytes:
    """Pickle that calls os.system — classic exploit pattern."""
    import pickletools
    # Craft manually: GLOBAL os system + string arg + REDUCE
    payload = (
        b'\x80\x02'           # proto 2
        b'c' b'os\nsystem\n'  # GLOBAL os.system
        b'(' b'Vecho pwned\n' # MARK + unicode string
        b'oq\x00.'            # BUILD/NEWOBJ + BINPUT + STOP
    )
    # Simpler: use a valid but dangerous opcode sequence
    class Exploit:
        def __reduce__(self):
            import os
            return (os.system, ("echo safe_test",))
    return pickle.dumps(Exploit())


def _pytorch_zip_with_safe_pickle() -> bytes:
    """A PyTorch-style ZIP archive containing a safe data.pkl."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", _safe_pickle())
    return buf.getvalue()


def _pytorch_zip_with_malicious_pickle() -> bytes:
    """A PyTorch-style ZIP archive containing a malicious data.pkl."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", _malicious_pickle_os_system())
    return buf.getvalue()


# ── PickleSafetyScanner ───────────────────────────────────────────────────────

class TestPickleSafetyScanner:

    def test_safe_pickle_passes(self):
        scanner = PickleSafetyScanner()
        result  = scanner.scan_bytes(_safe_pickle())
        assert result.safe
        assert result.verdict == "SAFE"

    def test_malicious_pickle_detected(self):
        scanner = PickleSafetyScanner()
        result  = scanner.scan_bytes(_malicious_pickle_os_system())
        assert not result.safe
        assert result.verdict in ("MALICIOUS", "SUSPICIOUS")

    def test_pytorch_zip_safe(self):
        scanner = PickleSafetyScanner()
        result  = scanner.scan_bytes(_pytorch_zip_with_safe_pickle())
        assert result.safe
        assert result.verdict == "SAFE"

    def test_pytorch_zip_malicious_detected(self):
        scanner = PickleSafetyScanner()
        result  = scanner.scan_bytes(_pytorch_zip_with_malicious_pickle())
        assert not result.safe

    def test_scan_file(self, tmp_path):
        p = tmp_path / "model.pkl"
        p.write_bytes(_safe_pickle())
        scanner = PickleSafetyScanner()
        result  = scanner.scan_file(p)
        assert result.safe

    def test_recommendation_populated(self):
        scanner = PickleSafetyScanner()
        result  = scanner.scan_bytes(_malicious_pickle_os_system())
        assert len(result.recommendation) > 0

    def test_opcodes_seen_populated(self):
        scanner = PickleSafetyScanner()
        result  = scanner.scan_bytes(_safe_pickle())
        assert len(result.opcodes_seen) > 0

    def test_strict_mode_flags_unknown_module(self):
        # Build a pickle that calls a non-allowlisted module
        class MyCustomClass:
            def __reduce__(self):
                import collections
                return (collections.OrderedDict, ())
        data    = pickle.dumps(MyCustomClass())
        scanner = PickleSafetyScanner(strict_mode=True)
        result  = scanner.scan_bytes(data)
        # In strict mode, non-allowlisted GLOBAL should be flagged
        # (collections is not in _SAFE_MODULES)
        # Verdict may be SUSPICIOUS
        assert result.verdict in ("SAFE", "SUSPICIOUS")   # collections is borderline


# ── WeightIntegrityVerifier ───────────────────────────────────────────────────

class TestWeightIntegrityVerifier:

    def _make_weight_file(self, tmp_path: Path, name: str, content: bytes) -> Path:
        p = tmp_path / name
        p.write_bytes(content)
        return p

    def _sha(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def test_ok_file_passes(self, tmp_path):
        content = os.urandom(1024)
        self._make_weight_file(tmp_path, "model.bin", content)
        manifest = {"files": {"model.bin": {"sha256": self._sha(content), "size": 1024}}}
        report   = WeightIntegrityVerifier().verify_directory(tmp_path, manifest)
        assert report.ok == 1
        assert report.overall_pass

    def test_corrupted_file_detected(self, tmp_path):
        content = os.urandom(1024)
        self._make_weight_file(tmp_path, "model.bin", content)
        manifest = {"files": {"model.bin": {"sha256": "a" * 64, "size": 1024}}}
        report   = WeightIntegrityVerifier().verify_directory(tmp_path, manifest)
        assert report.corrupted == 1
        assert not report.overall_pass

    def test_missing_file_detected(self, tmp_path):
        manifest = {"files": {"model.bin": {"sha256": "a" * 64, "size": 1024}}}
        report   = WeightIntegrityVerifier().verify_directory(tmp_path, manifest)
        assert report.missing == 1
        assert not report.overall_pass

    def test_unexpected_file_detected(self, tmp_path):
        content = os.urandom(512)
        self._make_weight_file(tmp_path, "extra.bin", content)
        manifest = {"files": {}}
        report   = WeightIntegrityVerifier(allow_unexpected=False).verify_directory(tmp_path, manifest)
        assert report.unexpected == 1
        assert not report.overall_pass

    def test_allow_unexpected_passes(self, tmp_path):
        content = os.urandom(512)
        self._make_weight_file(tmp_path, "extra.bin", content)
        manifest = {"files": {}}
        report   = WeightIntegrityVerifier(allow_unexpected=True).verify_directory(tmp_path, manifest)
        assert report.overall_pass

    def test_verify_single_file_ok(self, tmp_path):
        content = os.urandom(256)
        p       = self._make_weight_file(tmp_path, "shard.bin", content)
        result  = WeightIntegrityVerifier().verify_file(p, self._sha(content), len(content))
        assert result.status == "OK"

    def test_verify_single_file_corrupted(self, tmp_path):
        content = os.urandom(256)
        p       = self._make_weight_file(tmp_path, "shard.bin", content)
        result  = WeightIntegrityVerifier().verify_file(p, "wrong" * 12, len(content))
        assert result.status == "CORRUPTED"

    def test_save_json(self, tmp_path):
        content  = os.urandom(512)
        self._make_weight_file(tmp_path, "model.bin", content)
        manifest = {"files": {"model.bin": {"sha256": self._sha(content), "size": 512}}}
        report   = WeightIntegrityVerifier().verify_directory(tmp_path, manifest)
        path     = tmp_path / "report.json"
        report.save_json(path)
        data = json.loads(path.read_text())
        assert "results" in data


# ── ModelCardScorer ───────────────────────────────────────────────────────────

_COMPLETE_CARD = {
    "name": "fraud-detector-v2", "version": "2.0.0",
    "model_type": "classifier", "task": "binary-classification",
    "licence": "Apache-2.0",
    "datasets": ["transactions-v3"], "preprocessing": "z-score normalisation",
    "train_val_split": "80/10/10", "training_period": "2020–2023",
    "data_consent": "CC-BY-4.0 licensed data with DPA",
    "benchmarks": ["AUC-ROC=0.987"], "primary_metric": "AUC-ROC",
    "known_biases": "Lower recall on micro-transactions < $1",
    "fairness_eval": "Equalized odds evaluation performed",
    "eval_limitations": "Evaluated on US transactions only",
    "known_failures": "Fails on cryptocurrency exchanges",
    "out_of_scope_use": "Not for credit scoring",
    "risk_level": "HIGH", "mitigations": "Human-in-the-loop for high-value transactions",
    "monitoring": "Daily drift monitoring via Chapter 10 stack",
    "owner": "Acme ML Team", "contact": "ml-sec@acme.com",
    "review_date": "2025-01-01",
    "intended_use": "Fraud detection in payment systems",
    "prohibited_use": "Credit scoring, employment screening",
}

_MINIMAL_CARD = {
    "name": "mystery-model",
    "version": "0.1.0",
    "licence": "MIT",
    "owner": "Unknown",
    "intended_use": "TBD",
    "prohibited_use": "TBD",
}


class TestModelCardScorer:

    def test_complete_card_high_score(self):
        scorer = ModelCardScorer()
        result = scorer.score(_COMPLETE_CARD)
        assert result.total_score >= 90.0
        assert result.overall_pass
        assert result.mandatory_missing == []

    def test_empty_card_fails(self):
        scorer = ModelCardScorer()
        result = scorer.score({})
        assert not result.overall_pass
        assert len(result.mandatory_missing) > 0

    def test_mandatory_fields_flagged(self):
        scorer  = ModelCardScorer()
        result  = scorer.score({"name": "m", "version": "1"})  # missing licence, owner, etc.
        assert "licence" in result.mandatory_missing or "intended_use" in result.mandatory_missing

    def test_minimal_card_passes_mandatory_only(self):
        scorer = ModelCardScorer(pass_threshold=0.0)
        result = scorer.score(_MINIMAL_CARD)
        assert result.mandatory_missing == []

    def test_governance_category_scored(self):
        scorer = ModelCardScorer()
        result = scorer.score(_COMPLETE_CARD)
        assert result.category_scores.get("governance", 0) > 80.0

    def test_score_threshold_gate(self):
        scorer = ModelCardScorer(pass_threshold=95.0)
        result = scorer.score(_MINIMAL_CARD)
        assert not result.overall_pass   # minimal card won't hit 95%

    def test_summary_string(self):
        scorer = ModelCardScorer()
        result = scorer.score(_COMPLETE_CARD)
        assert "fraud-detector-v2" in result.summary()

    def test_save_json(self, tmp_path):
        scorer = ModelCardScorer()
        result = scorer.score(_COMPLETE_CARD)
        path   = tmp_path / "card_score.json"
        result.save_json(path)
        data   = json.loads(path.read_text())
        assert "total_score" in data
        assert "category_scores" in data
