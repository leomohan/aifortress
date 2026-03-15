"""
tests/test_dependency_scanning.py
AI Fortress · Chapter 8 · Code Sample 8.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from cve_scanner import CVEScanner, _version_in_range
from licence_checker import LicenceChecker
from transitive_risk_scorer import TransitiveRiskScorer


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_CVE_DB = {
    "CVE-2024-1001": {
        "description": "Remote code execution in numpy < 1.24.4",
        "cvss_v3_score": 9.8,
        "affected": [{"package": "numpy", "version_start": "1.0.0", "version_end": "1.24.4"}],
        "fix_version": "1.24.4",
        "published": "2024-01-15",
    },
    "CVE-2024-1002": {
        "description": "Path traversal in requests < 2.31.0",
        "cvss_v3_score": 6.5,
        "affected": [{"package": "requests", "version_start": "0.0.1", "version_end": "2.31.0"}],
        "fix_version": "2.31.0",
        "published": "2024-02-01",
    },
    "CVE-2024-1003": {
        "description": "Unsafe deserialization in torch < 2.1.0",
        "cvss_v3_score": 8.8,
        "affected": [{"package": "torch", "version_start": "1.0.0", "version_end": "2.1.0"}],
        "fix_version": "2.1.0",
        "published": "2024-03-01",
    },
}


# ── CVEScanner ────────────────────────────────────────────────────────────────

class TestCVEScanner:

    def test_vulnerable_package_detected(self):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        report  = scanner.scan({"numpy": "1.24.0"})
        assert report.vulnerable == 1
        assert report.findings[0].cve_id == "CVE-2024-1001"

    def test_patched_package_not_flagged(self):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        report  = scanner.scan({"numpy": "1.26.0"})  # > 1.24.4
        assert report.vulnerable == 0

    def test_training_package_multiplier_applied(self):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        report  = scanner.scan({"torch": "2.0.0"})
        finding = report.findings[0]
        # 8.8 × 1.5 = 13.2 → capped at 10.0
        assert finding.adjusted_score == 10.0
        assert finding.training_context is True

    def test_non_training_package_no_multiplier(self):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        report  = scanner.scan({"requests": "2.30.0"})
        finding = report.findings[0]
        assert finding.adjusted_score == finding.cvss_v3_score
        assert finding.training_context is False

    def test_overall_pass_no_critical_high(self):
        scanner = CVEScanner(SAMPLE_CVE_DB, fail_on_score=7.0)
        report  = scanner.scan({"requests": "2.30.0"})   # 6.5 score
        assert report.overall_pass  # below 7.0 gate

    def test_overall_fail_on_high(self):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        report  = scanner.scan({"numpy": "1.24.0"})  # 9.8 CRITICAL
        assert not report.overall_pass

    def test_scan_freeze_text(self):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        freeze  = "numpy==1.24.0\nrequests==2.31.0\n"
        report  = scanner.scan_freeze(freeze)
        assert report.vulnerable == 1
        assert report.findings[0].package == "numpy"

    def test_summary_string(self):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        report  = scanner.scan({"numpy": "1.26.0"})
        assert "CVE Scan" in report.summary()

    def test_save_json(self, tmp_path):
        scanner = CVEScanner(SAMPLE_CVE_DB)
        report  = scanner.scan({"numpy": "1.24.0"})
        path    = tmp_path / "cve.json"
        report.save_json(path)
        data = json.loads(path.read_text())
        assert "findings" in data

    def test_version_in_range(self):
        assert _version_in_range("1.24.0", "1.0.0", "1.24.4") is True
        assert _version_in_range("1.24.4", "1.0.0", "1.24.4") is False   # exclusive end
        assert _version_in_range("1.26.0", "1.0.0", "1.24.4") is False
        assert _version_in_range("0.9.0",  "1.0.0", "1.24.4") is False


# ── LicenceChecker ────────────────────────────────────────────────────────────

class TestLicenceChecker:

    def test_allowed_licence_passes(self):
        lc     = LicenceChecker()
        report = lc.check({"numpy": {"version": "1.26.0", "licence": "BSD-3-Clause"}})
        assert report.allowed == 1
        assert report.overall_pass

    def test_denied_licence_fails(self):
        lc     = LicenceChecker()
        report = lc.check({"agpl-lib": {"version": "1.0", "licence": "AGPL-3.0"}})
        assert report.denied == 1
        assert not report.overall_pass
        assert any(f.severity == "CRITICAL" for f in report.findings)

    def test_restricted_licence_requires_review(self):
        lc     = LicenceChecker()
        report = lc.check({"gpl-lib": {"version": "1.0", "licence": "GPL-3.0"}})
        assert report.restricted == 1
        # Restricted does not automatically fail (requires legal review)
        assert report.overall_pass is False   # actually fails due to restricted

    def test_unknown_licence_fails(self):
        lc     = LicenceChecker()
        report = lc.check({"mystery": {"version": "0.1", "licence": "NOASSERTION"}})
        assert report.unknown == 1
        assert not report.overall_pass

    def test_multiple_packages(self):
        lc     = LicenceChecker()
        report = lc.check({
            "numpy":    {"version": "1.26.0", "licence": "BSD-3-Clause"},
            "torch":    {"version": "2.2.0",  "licence": "BSD-3-Clause"},
            "agpl-lib": {"version": "1.0",    "licence": "AGPL-3.0"},
        })
        assert report.total_packages == 3
        assert report.allowed == 2
        assert report.denied  == 1

    def test_check_sbom(self):
        lc   = LicenceChecker()
        sbom = {
            "components": [
                {"name": "numpy", "version": "1.26.0",
                 "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
                {"name": "agpl-pkg", "version": "1.0",
                 "licenses": [{"license": {"id": "AGPL-3.0"}}]},
            ]
        }
        report = lc.check_sbom(sbom)
        assert report.denied == 1

    def test_save_json(self, tmp_path):
        lc     = LicenceChecker()
        report = lc.check({"numpy": {"version": "1.26.0", "licence": "MIT"}})
        path   = tmp_path / "licence.json"
        report.save_json(path)
        data   = json.loads(path.read_text())
        assert "findings" in data


# ── TransitiveRiskScorer ──────────────────────────────────────────────────────

class TestTransitiveRiskScorer:

    def test_direct_cve_scored(self):
        graph      = {"numpy": [], "torch": ["numpy"]}
        cve_scores = {"numpy": 9.8}
        scorer     = TransitiveRiskScorer()
        report     = scorer.score(graph, cve_scores)
        numpy_entry = next(e for e in report.entries if e.package == "numpy")
        assert numpy_entry.direct_cve_score == 9.8
        assert numpy_entry.risk_level in ("CRITICAL", "HIGH")

    def test_transitive_risk_propagated(self):
        graph      = {"torch": ["numpy"], "numpy": []}
        cve_scores = {"numpy": 9.8}
        scorer     = TransitiveRiskScorer(decay_factor=0.5)
        report     = scorer.score(graph, cve_scores)
        torch_entry = next(e for e in report.entries if e.package == "torch")
        # torch has no direct CVE but depends on vulnerable numpy
        assert torch_entry.direct_cve_score == 0.0
        assert torch_entry.transitive_score > 0.0
        assert "numpy" in torch_entry.vulnerable_deps

    def test_decay_reduces_score_with_depth(self):
        graph = {
            "app":    ["middleware"],
            "middleware": ["numpy"],
            "numpy": [],
        }
        cve_scores = {"numpy": 10.0}
        scorer_50  = TransitiveRiskScorer(decay_factor=0.5)
        scorer_10  = TransitiveRiskScorer(decay_factor=0.1)
        report_50  = scorer_50.score(graph, cve_scores)
        report_10  = scorer_10.score(graph, cve_scores)
        app_50 = next(e for e in report_50.entries if e.package == "app")
        app_10 = next(e for e in report_10.entries if e.package == "app")
        # Higher decay → higher transitive score for app
        assert app_50.transitive_score > app_10.transitive_score

    def test_no_cve_entry_risk_none(self):
        graph      = {"numpy": []}
        cve_scores = {}
        scorer     = TransitiveRiskScorer()
        report     = scorer.score(graph, cve_scores)
        entry      = report.entries[0]
        assert entry.risk_level == "NONE"
        assert entry.composite_score == 0.0

    def test_top_risk_sorted_descending(self):
        graph = {
            "a": [], "b": [], "c": [],
        }
        cve_scores = {"a": 9.8, "b": 5.0, "c": 2.0}
        scorer     = TransitiveRiskScorer()
        report     = scorer.score(graph, cve_scores)
        top        = report.top_risk(3)
        scores     = [e.composite_score for e in top]
        assert scores == sorted(scores, reverse=True)

    def test_high_risk_count(self):
        graph      = {"a": [], "b": [], "c": []}
        cve_scores = {"a": 9.8, "b": 8.0, "c": 3.0}
        scorer     = TransitiveRiskScorer()
        report     = scorer.score(graph, cve_scores)
        assert report.high_risk_count == 2   # 9.8 CRITICAL + 8.0 HIGH

    def test_save_json(self, tmp_path):
        graph      = {"numpy": [], "torch": ["numpy"]}
        cve_scores = {"numpy": 9.8}
        scorer     = TransitiveRiskScorer()
        report     = scorer.score(graph, cve_scores)
        path       = tmp_path / "risk.json"
        report.save_json(path)
        data = json.loads(path.read_text())
        assert "entries" in data
