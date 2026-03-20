"""
tests/test_evidence_collection.py
AI Fortress · Chapter 14 · Code Sample 14.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, hashlib, pytest
from pathlib import Path
from evidence_artefact import EvidenceCollector, EvidenceArtefact
from control_mapper import ControlMapper
from evidence_package_builder import EvidencePackageBuilder


# ── EvidenceCollector ─────────────────────────────────────────────────────────

class TestEvidenceCollector:

    def _col(self, name="test-audit"):
        return EvidenceCollector(name, collector_name="tester")

    def test_collect_returns_artefact(self):
        col = self._col()
        art = col.collect(b"policy content", "Policy v1", "policy_document",
                          ["CTRL-01"], "2026-Q1")
        assert art.artefact_id
        assert art.sha256

    def test_sha256_correct(self):
        col     = self._col()
        content = b"my evidence bytes"
        art     = col.collect(content, "doc", "log_export", ["C1"], "2026-Q1")
        expected = hashlib.sha256(content).hexdigest()
        assert art.sha256 == expected

    def test_inventory_count(self):
        col = self._col()
        col.collect(b"a", "a", "policy_document", ["C1"], "2026-Q1")
        col.collect(b"b", "b", "test_result",     ["C2"], "2026-Q1")
        inv = col.inventory()
        assert inv.total_artefacts == 2

    def test_for_control_filter(self):
        col = self._col()
        col.collect(b"x", "x", "policy_document", ["C1", "C2"], "2026-Q1")
        col.collect(b"y", "y", "test_result",     ["C3"],       "2026-Q1")
        arts = col.for_control("C1")
        assert len(arts) == 1

    def test_uncovered_controls(self):
        col = self._col()
        col.collect(b"x", "x", "policy_document", ["C1"], "2026-Q1")
        missing = col.uncovered_controls(["C1", "C2", "C3"])
        assert "C2" in missing and "C3" in missing
        assert "C1" not in missing

    def test_supersede(self):
        col = self._col()
        art = col.collect(b"v1", "doc v1", "policy_document", ["C1"], "2026-Q1")
        col.supersede(art.artefact_id, "replaced by v2")
        inv = col.inventory()
        superseded = [a for a in inv.artefacts if a.artefact_id == art.artefact_id]
        assert superseded[0].superseded

    def test_verify_integrity_pass(self):
        col     = self._col()
        content = b"unchanged content"
        art     = col.collect(content, "doc", "log_export", ["C1"], "2026-Q1")
        assert col.verify_integrity(art.artefact_id, content)

    def test_verify_integrity_fail(self):
        col = self._col()
        art = col.collect(b"original", "doc", "log_export", ["C1"], "2026-Q1")
        assert not col.verify_integrity(art.artefact_id, b"tampered")

    def test_persist_and_reload(self, tmp_path):
        p   = tmp_path / "evidence.jsonl"
        col = EvidenceCollector("audit", storage_path=p)
        col.collect(b"data", "doc", "policy_document", ["C1"], "2026-Q1")
        col2 = EvidenceCollector("audit", storage_path=p)
        assert len(col2.inventory().artefacts) == 1


# ── ControlMapper ──────────────────────────────────────────────────────────────

class TestControlMapper:

    def test_map_returns_entries(self):
        cm  = ControlMapper()
        res = cm.map("EU-AI-9", ["EU AI Act"], description="Risk management")
        assert res.control_id == "EU-AI-9"
        assert "EU AI Act" in res.frameworks

    def test_multi_framework_mapping(self):
        cm  = ControlMapper()
        res = cm.map("C1", ["EU AI Act", "ISO/IEC 42001"], description="Training data")
        assert len(res.frameworks) == 2

    def test_matrix_save_json(self, tmp_path):
        cm  = ControlMapper()
        cm.map("C1", ["EU AI Act"], description="Test")
        matrix = cm.matrix()
        p = tmp_path / "matrix.json"
        matrix.save_json(p)
        data = json.loads(p.read_text())
        assert "entries" in data

    def test_unknown_control_mapped(self):
        cm  = ControlMapper()
        res = cm.map("CUSTOM-99", ["Internal"], description="Custom control")
        assert res.control_id == "CUSTOM-99"


# ── EvidencePackageBuilder ─────────────────────────────────────────────────────

class TestEvidencePackageBuilder:

    def _setup(self):
        col = EvidenceCollector("Test Audit")
        col.collect(b"policy", "Policy", "policy_document", ["C1", "C2"], "2026-Q1")
        col.collect(b"test",   "Tests",  "test_result",     ["C3"],       "2026-Q1")
        required = {
            "C1": "Framework-A",
            "C2": "Framework-A",
            "C3": "Framework-B",
            "C4": "Framework-B",   # uncovered
        }
        return col, required

    def test_build_package(self):
        col, req = self._setup()
        pkg = EvidencePackageBuilder(req).build(col, "2026-Q1")
        assert pkg.package_id
        assert pkg.total_controls == 4

    def test_coverage_correct(self):
        col, req = self._setup()
        pkg = EvidencePackageBuilder(req).build(col, "2026-Q1")
        assert pkg.satisfied_controls == 3
        assert pkg.outstanding_controls == 1
        assert abs(pkg.coverage_pct - 0.75) < 0.01

    def test_coverage_grade(self):
        col, req = self._setup()
        pkg = EvidencePackageBuilder(req).build(col, "2026-Q1")
        assert pkg.coverage_grade() in "ABCDF"

    def test_package_hash_set(self):
        col, req = self._setup()
        pkg = EvidencePackageBuilder(req).build(col, "2026-Q1")
        assert len(pkg.package_hash) == 64

    def test_package_hash_deterministic(self):
        """Same artefacts must produce same hash."""
        col, req = self._setup()
        p1 = EvidencePackageBuilder(req).build(col, "2026-Q1")
        p2 = EvidencePackageBuilder(req).build(col, "2026-Q1")
        assert p1.package_hash == p2.package_hash

    def test_framework_summary_populated(self):
        col, req = self._setup()
        pkg = EvidencePackageBuilder(req).build(col, "2026-Q1")
        assert "Framework-A" in pkg.framework_summary
        assert "Framework-B" in pkg.framework_summary

    def test_save_json(self, tmp_path):
        col, req = self._setup()
        pkg = EvidencePackageBuilder(req).build(col, "2026-Q1")
        p   = tmp_path / "package.json"
        pkg.save_json(p)
        data = json.loads(p.read_text())
        assert "package_id" in data
        assert "coverage_pct" in data

    def test_summary_string(self):
        col, req = self._setup()
        pkg = EvidencePackageBuilder(req).build(col, "2026-Q1")
        assert "Test Audit" in pkg.summary()

    def test_all_grade_thresholds():
        from evidence_package_builder import EvidencePackage
        import dataclasses

        def _pkg(cov):
            return EvidencePackage(
                package_id="x", audit_name="t", prepared_by="t",
                prepared_at="2026", audit_period="Q1",
                total_artefacts=10, total_controls=100,
                satisfied_controls=int(cov * 100),
                outstanding_controls=int((1 - cov) * 100),
                coverage_pct=cov, artefacts=[], control_coverage=[],
                framework_summary={}, package_hash="abc",
            )

        assert _pkg(0.97).coverage_grade() == "A"
        assert _pkg(0.88).coverage_grade() == "B"
        assert _pkg(0.75).coverage_grade() == "C"
        assert _pkg(0.55).coverage_grade() == "D"
        assert _pkg(0.40).coverage_grade() == "F"
