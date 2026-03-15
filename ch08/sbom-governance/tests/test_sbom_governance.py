"""
tests/test_sbom_governance.py
AI Fortress · Chapter 8 · Code Sample 8.E
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from pathlib import Path

from sbom_completeness_scorer import SBOMCompletenessScorer
from licence_policy_gate import LicencePolicyGate, LicencePolicyError
from blocklist_checker import BlocklistChecker, BlocklistViolationError
from sbom_registry import SBOMRegistry


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _comp(name, version="1.0.0", lic="MIT", purl=None, ctype="library", hashes=True):
    c = {
        "type":     ctype,
        "name":     name,
        "version":  version,
        "purl":     purl or f"pkg:pypi/{name.lower()}@{version}",
        "licenses": [{"license": {"id": lic}}] if lic else [],
    }
    if hashes:
        c["hashes"] = [{"alg": "SHA-256", "content": "a" * 64}]
    return c


def _sbom(name, version="1.0.0", components=None):
    return {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:test-123",
        "metadata": {
            "timestamp": "2024-01-01T00:00:00Z",
            "tools":     [{"name": "sbom-generator"}],
            "authors":   [{"name": "AI Fortress"}],
            "component": {"name": name, "version": version, "type": "application",
                          "purl": f"pkg:generic/{name}@{version}"},
        },
        "components": components or [],
    }


# ─── SBOMCompletenessScorer ───────────────────────────────────────────────────

class TestSBOMCompletenessScorer:

    def test_well_formed_sbom_high_score(self):
        comps  = [_comp("numpy", "1.26.0"), _comp("torch", "2.2.0", ctype="framework")]
        sbom   = _sbom("ml-project", "1.0.0", comps)
        scorer = SBOMCompletenessScorer(pass_threshold=50.0)
        result = scorer.score(sbom)
        assert result.total_score > 50.0

    def test_empty_sbom_fails(self):
        sbom   = _sbom("empty-project")
        scorer = SBOMCompletenessScorer()
        result = scorer.score(sbom)
        assert not result.overall_pass

    def test_missing_metadata_penalised(self):
        sbom   = {"bomFormat": "CycloneDX", "components": [_comp("numpy")]}
        scorer = SBOMCompletenessScorer(pass_threshold=0.0)
        result = scorer.score(sbom)
        assert result.dimension_scores.get("metadata", 0) == 0.0

    def test_missing_purls_penalised(self):
        comps  = [{"type": "library", "name": "numpy", "version": "1.26.0"}]  # no purl
        sbom   = _sbom("p", "1.0.0", comps)
        scorer = SBOMCompletenessScorer()
        result = scorer.score(sbom)
        assert any("PURL" in i for i in result.issues)

    def test_save_json(self, tmp_path):
        sbom   = _sbom("p", "1.0.0", [_comp("numpy")])
        scorer = SBOMCompletenessScorer()
        result = scorer.score(sbom)
        path   = tmp_path / "completeness.json"
        result.save_json(path)
        data   = json.loads(path.read_text())
        assert "total_score" in data

    def test_summary_string(self):
        sbom   = _sbom("my-model", "2.0.0", [_comp("numpy")])
        scorer = SBOMCompletenessScorer()
        result = scorer.score(sbom)
        assert "my-model" in result.summary()

    def test_score_file(self, tmp_path):
        sbom = _sbom("proj", "1.0.0", [_comp("numpy")])
        f    = tmp_path / "sbom.json"
        f.write_text(json.dumps(sbom))
        scorer = SBOMCompletenessScorer()
        result = scorer.score_file(f)
        assert result.total_components == 1


# ─── LicencePolicyGate ────────────────────────────────────────────────────────

class TestLicencePolicyGate:

    def test_all_allowed_passes(self):
        comps = [_comp("numpy", lic="MIT"), _comp("torch", lic="BSD-3-Clause")]
        sbom  = _sbom("proj", components=comps)
        gate  = LicencePolicyGate()
        rep   = gate.check(sbom)
        assert rep.passed
        assert rep.allowed == 2

    def test_denied_licence_fails(self):
        comps = [_comp("agpl-lib", lic="AGPL-3.0")]
        sbom  = _sbom("proj", components=comps)
        gate  = LicencePolicyGate()
        rep   = gate.check(sbom)
        assert not rep.passed
        assert rep.denied == 1

    def test_unknown_licence_fails(self):
        comps = [_comp("mystery", lic="")]
        sbom  = _sbom("proj", components=comps)
        gate  = LicencePolicyGate()
        rep   = gate.check(sbom)
        assert not rep.passed
        assert rep.unknown == 1

    def test_restricted_by_default_does_not_block(self):
        comps = [_comp("gpl-lib", lic="GPL-3.0")]
        sbom  = _sbom("proj", components=comps)
        gate  = LicencePolicyGate(block_restricted=False)
        rep   = gate.check(sbom)
        assert rep.passed
        assert rep.restricted == 1

    def test_restricted_with_block_fails(self):
        comps = [_comp("gpl-lib", lic="GPL-3.0")]
        sbom  = _sbom("proj", components=comps)
        gate  = LicencePolicyGate(block_restricted=True)
        rep   = gate.check(sbom)
        assert not rep.passed

    def test_enforce_raises_on_denied(self):
        comps = [_comp("agpl-lib", lic="AGPL-3.0")]
        sbom  = _sbom("proj", components=comps)
        with pytest.raises(LicencePolicyError) as exc:
            LicencePolicyGate().enforce(sbom)
        assert exc.value.report.denied == 1

    def test_enforce_passes_on_clean(self):
        comps = [_comp("numpy", lic="BSD-3-Clause")]
        sbom  = _sbom("proj", components=comps)
        rep   = LicencePolicyGate().enforce(sbom)
        assert rep.passed

    def test_save_json(self, tmp_path):
        comps = [_comp("numpy", lic="MIT")]
        sbom  = _sbom("proj", components=comps)
        rep   = LicencePolicyGate().check(sbom)
        path  = tmp_path / "lic_report.json"
        rep.save_json(path)
        data  = json.loads(path.read_text())
        assert "findings" in data


# ─── BlocklistChecker ─────────────────────────────────────────────────────────

CUSTOM_BL = {
    "evil-pkg": {"reason": "Known malware", "severity": "CRITICAL",
                 "cve": "", "added": "2024-01-01"},
    "pillow":   {"reason": "Old versions vulnerable", "severity": "HIGH",
                 "cve": "CVE-2022-45199", "version_below": "9.3.0", "added": "2022-11-15"},
}


class TestBlocklistChecker:

    def test_clean_sbom_passes(self):
        comps = [_comp("numpy"), _comp("torch")]
        sbom  = _sbom("proj", components=comps)
        rep   = BlocklistChecker(CUSTOM_BL).check(sbom)
        assert rep.overall_pass
        assert len(rep.hits) == 0

    def test_blocklisted_package_detected(self):
        comps = [_comp("evil-pkg")]
        sbom  = _sbom("proj", components=comps)
        rep   = BlocklistChecker(CUSTOM_BL).check(sbom)
        assert not rep.overall_pass
        assert rep.hits[0].component == "evil-pkg"
        assert rep.hits[0].severity  == "CRITICAL"

    def test_case_insensitive_match(self):
        comps = [_comp("Evil-Pkg")]
        sbom  = _sbom("proj", components=comps)
        rep   = BlocklistChecker(CUSTOM_BL).check(sbom)
        assert not rep.overall_pass

    def test_version_below_range_flagged(self):
        comps = [_comp("pillow", version="9.0.0")]
        sbom  = _sbom("proj", components=comps)
        rep   = BlocklistChecker(CUSTOM_BL).check(sbom)
        assert not rep.overall_pass

    def test_version_above_range_not_flagged(self):
        comps = [_comp("pillow", version="9.5.0")]
        sbom  = _sbom("proj", components=comps)
        rep   = BlocklistChecker(CUSTOM_BL).check(sbom)
        assert rep.overall_pass

    def test_enforce_raises_on_hit(self):
        comps = [_comp("evil-pkg")]
        sbom  = _sbom("proj", components=comps)
        with pytest.raises(BlocklistViolationError) as exc:
            BlocklistChecker(CUSTOM_BL).enforce(sbom)
        assert "evil-pkg" in str(exc.value)

    def test_enforce_passes_clean(self):
        comps = [_comp("numpy")]
        sbom  = _sbom("proj", components=comps)
        rep   = BlocklistChecker(CUSTOM_BL).enforce(sbom)
        assert rep.overall_pass

    def test_load_blocklist_file(self, tmp_path):
        extra = {"extra-evil": {"reason": "Extra bad", "severity": "CRITICAL",
                                "cve": "", "added": "2024-01-01"}}
        bl_file = tmp_path / "extra.json"
        bl_file.write_text(json.dumps(extra))
        checker = BlocklistChecker({})
        checker.load_blocklist_file(bl_file)
        comps = [_comp("extra-evil")]
        sbom  = _sbom("proj", components=comps)
        rep   = checker.check(sbom)
        assert not rep.overall_pass

    def test_save_json(self, tmp_path):
        comps = [_comp("evil-pkg")]
        sbom  = _sbom("proj", components=comps)
        rep   = BlocklistChecker(CUSTOM_BL).check(sbom)
        path  = tmp_path / "bl_report.json"
        rep.save_json(path)
        data  = json.loads(path.read_text())
        assert "hits" in data


# ─── SBOMRegistry ────────────────────────────────────────────────────────────

class TestSBOMRegistry:

    def _make_sbom(self, name, version):
        return _sbom(name, version, [_comp("numpy"), _comp("torch")])

    def test_register_and_retrieve(self, tmp_path):
        reg   = SBOMRegistry(tmp_path / "reg")
        sbom  = self._make_sbom("fraud-detector", "1.0.0")
        entry = reg.register(sbom, approved_by="alice")
        assert entry.project == "fraud-detector"
        assert entry.version == "1.0.0"
        assert entry.component_count == 2

    def test_get_by_project_version(self, tmp_path):
        reg  = SBOMRegistry(tmp_path / "reg")
        sbom = self._make_sbom("fraud-detector", "2.0.0")
        reg.register(sbom)
        loaded = reg.get("fraud-detector", "2.0.0")
        assert loaded["metadata"]["component"]["name"] == "fraud-detector"

    def test_latest_returns_most_recent(self, tmp_path):
        reg  = SBOMRegistry(tmp_path / "reg")
        reg.register(self._make_sbom("fraud-detector", "1.0.0"))
        reg.register(self._make_sbom("fraud-detector", "2.0.0"))
        latest = reg.latest("fraud-detector")
        assert latest is not None

    def test_list_projects(self, tmp_path):
        reg = SBOMRegistry(tmp_path / "reg")
        reg.register(self._make_sbom("proj-a", "1.0.0"))
        reg.register(self._make_sbom("proj-b", "1.0.0"))
        projects = reg.list_projects()
        assert "proj-a" in projects
        assert "proj-b" in projects

    def test_list_versions(self, tmp_path):
        reg = SBOMRegistry(tmp_path / "reg")
        reg.register(self._make_sbom("proj", "1.0.0"))
        reg.register(self._make_sbom("proj", "2.0.0"))
        versions = reg.list_versions("proj")
        assert "1.0.0" in versions
        assert "2.0.0" in versions

    def test_approve_recorded(self, tmp_path):
        reg  = SBOMRegistry(tmp_path / "reg")
        reg.register(self._make_sbom("proj", "1.0.0"))
        reg.approve("proj", "1.0.0", approved_by="security-team")
        entry = reg.get_entry("proj", "1.0.0")
        assert entry.approved_by == "security-team"
        assert entry.approved_at != ""

    def test_gate_result_recorded(self, tmp_path):
        reg  = SBOMRegistry(tmp_path / "reg")
        reg.register(self._make_sbom("proj", "1.0.0"))
        reg.record_gate_result("proj", "1.0.0", "licence_policy", True)
        reg.record_gate_result("proj", "1.0.0", "blocklist",       True)
        entry = reg.get_entry("proj", "1.0.0")
        assert entry.gate_results["licence_policy"] is True

    def test_registry_persists_across_instances(self, tmp_path):
        reg_dir = tmp_path / "reg"
        reg1    = SBOMRegistry(reg_dir)
        reg1.register(self._make_sbom("proj", "1.0.0"))
        reg2    = SBOMRegistry(reg_dir)        # new instance, same directory
        assert "proj" in reg2.list_projects()

    def test_missing_project_raises(self, tmp_path):
        reg = SBOMRegistry(tmp_path / "reg")
        with pytest.raises(KeyError):
            reg.get("nonexistent", "1.0.0")

    def test_latest_unknown_project_returns_none(self, tmp_path):
        reg = SBOMRegistry(tmp_path / "reg")
        assert reg.latest("does-not-exist") is None
