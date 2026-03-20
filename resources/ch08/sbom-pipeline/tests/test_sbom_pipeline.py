"""
tests/test_sbom_pipeline.py
AI Fortress · Chapter 8 · Code Sample 8.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from pathlib import Path

from sbom_generator import SBOMGenerator, SBOMComponent
from model_card_extension import (
    ModelCardExtension, ModelCardMetadata, DatasetProvenance, BaseModelLineage
)
from sbom_differ import SBOMDiffer, SBOMDriftError

FREEZE_TEXT = """\
# pip freeze snapshot
numpy==1.26.0
torch==2.2.0
scikit-learn==1.4.0
requests==2.31.0
cryptography==42.0.0
"""


class TestSBOMGenerator:
    def test_from_freeze_text_parses_components(self):
        gen  = SBOMGenerator("ml-project", "1.0.0")
        sbom = gen.from_freeze_text(FREEZE_TEXT)
        names = [c.name.lower() for c in sbom.components]
        assert "numpy" in names
        assert "torch" in names
        assert "requests" in names

    def test_framework_type_assigned(self):
        gen  = SBOMGenerator("ml-project")
        sbom = gen.from_freeze_text(FREEZE_TEXT)
        torch_comp = next(c for c in sbom.components if c.name.lower() == "torch")
        assert torch_comp.type == "framework"

    def test_library_type_assigned(self):
        gen  = SBOMGenerator("ml-project")
        sbom = gen.from_freeze_text(FREEZE_TEXT)
        req_comp = next(c for c in sbom.components if c.name.lower() == "requests")
        assert req_comp.type == "library"

    def test_purl_format(self):
        gen  = SBOMGenerator("ml-project")
        sbom = gen.from_freeze_text(FREEZE_TEXT)
        for comp in sbom.components:
            assert comp.purl.startswith("pkg:pypi/")
            assert "@" in comp.purl

    def test_comments_and_blanks_skipped(self):
        gen  = SBOMGenerator("ml-project")
        sbom = gen.from_freeze_text("# comment\n\nnumpy==1.26.0\n")
        assert len(sbom.components) == 1

    def test_to_dict_cyclonedx_format(self):
        gen  = SBOMGenerator("ml-project")
        sbom = gen.from_freeze_text("numpy==1.26.0\n")
        d    = sbom.to_dict()
        assert d["bomFormat"]   == "CycloneDX"
        assert d["specVersion"] == "1.4"
        assert "components" in d
        assert len(d["components"]) == 1

    def test_save_and_load(self, tmp_path):
        gen  = SBOMGenerator("ml-project", "2.0.0")
        sbom = gen.from_freeze_text(FREEZE_TEXT)
        path = tmp_path / "sbom.json"
        gen.save(sbom, path)
        loaded = SBOMGenerator.load(path)
        assert loaded["bomFormat"] == "CycloneDX"
        assert len(loaded["components"]) == len(sbom.components)

    def test_metadata_fields(self):
        gen  = SBOMGenerator("fraud-detector", "3.1.0", author="Acme Corp")
        sbom = gen.from_freeze_text("numpy==1.26.0\n")
        d    = sbom.to_dict()
        assert d["metadata"]["component"]["name"]    == "fraud-detector"
        assert d["metadata"]["component"]["version"] == "3.1.0"
        assert d["metadata"]["authors"][0]["name"]   == "Acme Corp"

    def test_from_requirements_txt(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("numpy==1.26.0\ntorch==2.2.0\n")
        gen  = SBOMGenerator("ml-project")
        sbom = gen.from_requirements_txt(req_file)
        assert len(sbom.components) == 2

    def test_from_component_list(self):
        gen  = SBOMGenerator("ml-project")
        comp = SBOMComponent(type="library", name="numpy", version="1.26.0",
                              purl="pkg:pypi/numpy@1.26.0")
        sbom = gen.from_component_list([comp])
        assert len(sbom.components) == 1


class TestModelCardExtension:
    def _make_metadata(self):
        return ModelCardMetadata(
            model_name    = "fraud-detector-v2",
            model_version = "2.0.0",
            model_type    = "classifier",
            task          = "binary-classification",
            datasets      = [DatasetProvenance(
                name="transactions-v3", version="3.0",
                source_url="https://data.example.com/transactions",
                licence="CC-BY-4.0", sha256="abc123",
                record_count=1_000_000,
            )],
            base_models   = [BaseModelLineage(
                name="bert-base-uncased", version="1.0",
                registry="huggingface",
                registry_url="https://huggingface.co/bert-base-uncased",
                licence="Apache-2.0",
            )],
            frameworks    = ["torch==2.2.0"],
            benchmarks    = [{"name": "AUC-ROC", "score": 0.987}],
            model_card_url = "https://models.example.com/fraud-v2/card",
            intended_use  = "Fraud detection in payment systems.",
        )

    def test_extend_adds_model_component(self):
        gen  = SBOMGenerator("fraud-detector-v2")
        sbom = gen.from_freeze_text("numpy==1.26.0\n")
        ext  = ModelCardExtension(self._make_metadata())
        ext.extend(sbom)
        model_comps = [c for c in sbom.components if c.type == "machine-learning-model"]
        assert len(model_comps) >= 1
        assert model_comps[0].name == "fraud-detector-v2"

    def test_extend_adds_dataset_component(self):
        gen  = SBOMGenerator("fraud-detector-v2")
        sbom = gen.from_freeze_text("numpy==1.26.0\n")
        ext  = ModelCardExtension(self._make_metadata())
        ext.extend(sbom)
        data_comps = [c for c in sbom.components if c.type == "data"]
        assert len(data_comps) == 1
        assert data_comps[0].name == "transactions-v3"

    def test_extend_adds_base_model_lineage(self):
        gen  = SBOMGenerator("fraud-detector-v2")
        sbom = gen.from_freeze_text("numpy==1.26.0\n")
        ext  = ModelCardExtension(self._make_metadata())
        ext.extend(sbom)
        ml_comps = [c for c in sbom.components if c.type == "machine-learning-model"]
        names    = [c.name for c in ml_comps]
        assert "bert-base-uncased" in names

    def test_model_card_url_in_ext_refs(self):
        gen  = SBOMGenerator("fraud-detector-v2")
        sbom = gen.from_freeze_text("numpy==1.26.0\n")
        ext  = ModelCardExtension(self._make_metadata())
        ext.extend(sbom)
        model_comp = next(c for c in sbom.components if c.name == "fraud-detector-v2")
        urls = [r["url"] for r in model_comp.external_references]
        assert "https://models.example.com/fraud-v2/card" in urls


class TestSBOMDiffer:
    def _make_sbom_dict(self, components: list) -> dict:
        return {
            "bomFormat":   "CycloneDX",
            "specVersion": "1.4",
            "components":  components,
        }

    def _comp(self, name, version, lic="MIT"):
        return {"name": name, "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "licenses": [{"license": {"id": lic}}]}

    def test_no_changes_clean(self):
        sbom = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        diff = SBOMDiffer().diff(sbom, sbom)
        assert not diff.drift_detected
        assert diff.total_changes == 0

    def test_added_component_detected(self):
        baseline = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        current  = self._make_sbom_dict([
            self._comp("numpy", "1.26.0"),
            self._comp("requests", "2.31.0"),
        ])
        diff = SBOMDiffer().diff(baseline, current)
        assert len(diff.added) == 1
        assert diff.added[0].name == "requests"

    def test_removed_component_detected(self):
        baseline = self._make_sbom_dict([
            self._comp("numpy", "1.26.0"),
            self._comp("requests", "2.31.0"),
        ])
        current  = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        diff     = SBOMDiffer().diff(baseline, current)
        assert len(diff.removed) == 1
        assert diff.removed[0].name == "requests"

    def test_version_change_detected(self):
        baseline = self._make_sbom_dict([self._comp("numpy", "1.25.0")])
        current  = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        diff     = SBOMDiffer().diff(baseline, current)
        assert len(diff.version_changes) == 1
        assert diff.version_changes[0].old_value == "1.25.0"
        assert diff.version_changes[0].new_value == "1.26.0"

    def test_licence_change_detected(self):
        baseline = self._make_sbom_dict([self._comp("numpy", "1.26.0", lic="MIT")])
        current  = self._make_sbom_dict([self._comp("numpy", "1.26.0", lic="GPL-3.0")])
        diff     = SBOMDiffer().diff(baseline, current)
        assert len(diff.licence_changes) == 1
        assert "GPL-3.0" in diff.licence_changes[0].new_value

    def test_unapproved_component_raises(self):
        baseline = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        current  = self._make_sbom_dict([
            self._comp("numpy", "1.26.0"),
            self._comp("evilpackage", "0.1.0"),
        ])
        differ = SBOMDiffer(approved_components={"numpy", "requests"})
        diff   = differ.diff(baseline, current)
        assert "evilpackage" in diff.unapproved
        with pytest.raises(SBOMDriftError) as exc:
            differ.enforce(diff)
        assert "evilpackage" in str(exc.value)

    def test_approved_component_no_error(self):
        baseline = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        current  = self._make_sbom_dict([
            self._comp("numpy", "1.26.0"),
            self._comp("requests", "2.31.0"),
        ])
        differ = SBOMDiffer(approved_components={"numpy", "requests"})
        diff   = differ.diff(baseline, current)
        assert diff.unapproved == []
        differ.enforce(diff)   # should not raise

    def test_diff_save_json(self, tmp_path):
        baseline = self._make_sbom_dict([self._comp("numpy", "1.25.0")])
        current  = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        diff     = SBOMDiffer().diff(baseline, current)
        path     = tmp_path / "diff.json"
        diff.save_json(path)
        data = json.loads(path.read_text())
        assert "version_changes" in data

    def test_summary_string_drift(self):
        baseline = self._make_sbom_dict([self._comp("numpy", "1.25.0")])
        current  = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        diff     = SBOMDiffer().diff(baseline, current)
        assert "drift" in diff.summary().lower()

    def test_summary_string_clean(self):
        sbom = self._make_sbom_dict([self._comp("numpy", "1.26.0")])
        diff = SBOMDiffer().diff(sbom, sbom)
        assert "No SBOM drift" in diff.summary()
