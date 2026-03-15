"""
tests/test_model_cards.py
AI Fortress · Chapter 12 · Code Sample 12.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from pathlib import Path

from metadata_extractor import MetadataExtractor, ModelMetadata
from risk_bias_documenter import RiskBiasDocumenter, BiasFinding
from evaluation_formatter import EvaluationFormatter, MetricResult
from model_card_schema import ModelCardBuilder


def _full_meta(**overrides):
    defaults = dict(
        model_name="fraud-detector", version="2.0.0",
        architecture="XGBoost", task_type="tabular-classification",
        training_framework="scikit-learn", primary_contact="ml-team@co.com",
        license="Apache-2.0",
        intended_use="Detect fraudulent transactions at checkout.",
        dataset_references=["internal-fraud-db-v3"],
    )
    defaults.update(overrides)
    return MetadataExtractor().build(**defaults)


# ── MetadataExtractor ─────────────────────────────────────────────────────────

class TestMetadataExtractor:

    def test_valid_metadata(self):
        meta = _full_meta()
        ext  = MetadataExtractor()
        val  = ext.validate(meta)
        assert val.valid

    def test_missing_required_field(self):
        ext  = MetadataExtractor()
        meta = ext.build(model_name="m", version="1.0.0")  # missing many fields
        val  = ext.validate(meta)
        assert not val.valid
        assert "architecture" in val.missing_required

    def test_recommended_missing_warning(self):
        ext  = MetadataExtractor()
        meta = ext.build(
            model_name="m", version="1.0.0", architecture="BERT",
            task_type="text-classification", training_framework="PyTorch",
            primary_contact="x@y.com", license="MIT"
        )
        val = ext.validate(meta)
        assert val.valid
        assert "dataset_references" in val.missing_recommended

    def test_unknown_task_type_warning(self):
        meta = _full_meta(task_type="mind-reading")
        val  = MetadataExtractor().validate(meta)
        assert any("task_type" in w for w in val.warnings)

    def test_extra_fields_stored(self):
        ext  = MetadataExtractor()
        meta = ext.build(**{**_full_meta().__dict__, "custom_field": "value"})
        assert meta.extra.get("custom_field") == "value"

    def test_from_dict(self):
        d   = _full_meta().to_dict()
        ext = MetadataExtractor()
        m2  = ext.from_dict(d)
        assert m2.model_name == "fraud-detector"

    def test_save_and_load_json(self, tmp_path):
        p   = tmp_path / "meta.json"
        p.write_text(json.dumps(_full_meta().to_dict()), encoding="utf-8")
        ext = MetadataExtractor()
        m2  = ext.from_json(p)
        assert m2.version == "2.0.0"


# ── RiskBiasDocumenter ────────────────────────────────────────────────────────

class TestRiskBiasDocumenter:

    def test_build_valid(self):
        doc = RiskBiasDocumenter().build(
            eu_ai_act_tier   = "high",
            eu_ai_act_reason = "Automated credit decision.",
            known_limitations = ["Degrades on non-US addresses"],
            bias_findings    = [{"dimension": "gender", "description": "3% gap",
                                  "severity": "moderate"}],
            human_oversight  = "Human review required for edge cases.",
        )
        assert doc.eu_ai_act_tier == "high"
        assert len(doc.bias_findings) == 1

    def test_invalid_tier_raises(self):
        with pytest.raises(ValueError, match="Invalid EU AI Act tier"):
            RiskBiasDocumenter().build("extreme", "reason")

    def test_validate_high_risk_without_oversight(self):
        doc    = RiskBiasDocumenter().build("high", "Credit scoring",
                                             known_limitations=["Some limits"])
        issues = RiskBiasDocumenter().validate(doc)
        assert any("oversight" in i for i in issues)

    def test_validate_no_limitations_warning(self):
        doc    = RiskBiasDocumenter().build("minimal", "Spam filter")
        issues = RiskBiasDocumenter().validate(doc)
        assert any("limitations" in i for i in issues)

    def test_bias_finding_object_accepted(self):
        bf  = BiasFinding("age", "Worse on >65", "moderate", "Resampling")
        doc = RiskBiasDocumenter().build(
            "limited", "Chatbot",
            known_limitations=["Hallucinations"],
            bias_findings=[bf],
        )
        assert doc.bias_findings[0].dimension == "age"

    def test_to_dict_serialisable(self):
        doc = RiskBiasDocumenter().build("minimal", "Spam filter",
                                          known_limitations=["Some"])
        d   = doc.to_dict()
        assert json.dumps(d)   # no serialisation error


# ── EvaluationFormatter ───────────────────────────────────────────────────────

class TestEvaluationFormatter:

    def _results(self):
        return [
            MetricResult("accuracy", 0.92, "test-set"),
            MetricResult("f1",       0.89, "test-set"),
            MetricResult("accuracy", 0.85, "holdout-2024"),
            # sliced results
            MetricResult("accuracy", 0.94, "test-set", slice_name="gender:male"),
            MetricResult("accuracy", 0.81, "test-set", slice_name="gender:female"),
            MetricResult("accuracy", 0.93, "test-set", slice_name="gender:non-binary"),
        ]

    def test_format_returns_report(self):
        fmt    = EvaluationFormatter()
        report = fmt.format(self._results())
        assert len(report.results) == len(self._results())

    def test_gap_detected(self):
        fmt    = EvaluationFormatter(gap_threshold_notable=0.05)
        report = fmt.format(self._results())
        assert len(report.performance_gaps) > 0

    def test_gap_severity_critical(self):
        fmt  = EvaluationFormatter(gap_threshold_critical=0.05)
        results = [
            MetricResult("f1", 0.95, "ds", slice_name="geo:US"),
            MetricResult("f1", 0.80, "ds", slice_name="geo:EU"),
        ]
        report = fmt.format(results)
        assert any(g.severity == "critical" for g in report.performance_gaps)

    def test_gap_below_threshold_not_reported(self):
        fmt  = EvaluationFormatter(gap_threshold_notable=0.10)
        results = [
            MetricResult("f1", 0.91, "ds", slice_name="age:young"),
            MetricResult("f1", 0.90, "ds", slice_name="age:old"),
        ]
        report = fmt.format(results)
        assert all(g.gap >= 0.10 for g in report.performance_gaps)

    def test_summary_table_markdown(self):
        fmt    = EvaluationFormatter()
        report = fmt.format(self._results())
        table  = report.summary_table()
        assert "accuracy" in table
        assert "test-set" in table
        assert "|" in table

    def test_no_slices_no_gaps(self):
        fmt     = EvaluationFormatter()
        results = [MetricResult("acc", 0.9, "test")]
        report  = fmt.format(results)
        assert len(report.performance_gaps) == 0

    def test_to_dict_serialisable(self):
        fmt    = EvaluationFormatter()
        report = fmt.format(self._results())
        assert json.dumps(report.to_dict())


# ── ModelCardBuilder ──────────────────────────────────────────────────────────

class TestModelCardBuilder:

    def _risk(self):
        return RiskBiasDocumenter().build(
            "limited", "Fraud detection chatbot assistant.",
            known_limitations=["Accuracy drops on non-English inputs."],
        )

    def _eval(self):
        return EvaluationFormatter().format([
            MetricResult("accuracy", 0.92, "test-set"),
            MetricResult("f1",       0.88, "test-set"),
        ])

    def test_build_minimal(self):
        card = ModelCardBuilder().with_metadata(_full_meta()).build()
        assert card.card_id
        assert card.metadata.model_name == "fraud-detector"
        assert not card.finalised

    def test_build_with_all_sections(self):
        card = (ModelCardBuilder()
                .with_metadata(_full_meta())
                .with_risk(self._risk())
                .with_evaluation(self._eval())
                .build())
        assert card.risk is not None
        assert card.evaluation is not None

    def test_build_without_metadata_raises(self):
        with pytest.raises(ValueError, match="requires metadata"):
            ModelCardBuilder().build()

    def test_build_invalid_metadata_raises(self):
        ext  = MetadataExtractor()
        meta = ext.build(model_name="m")   # missing required fields
        with pytest.raises(ValueError, match="Metadata validation failed"):
            ModelCardBuilder().with_metadata(meta).build()

    def test_finalise(self):
        builder = ModelCardBuilder()
        card    = builder.with_metadata(_full_meta()).build()
        builder.finalise(card, "compliance-officer@co.com")
        assert card.finalised
        assert card.finalised_by == "compliance-officer@co.com"
        assert card.finalised_at

    def test_save_json(self, tmp_path):
        card = ModelCardBuilder().with_metadata(_full_meta()).build()
        p    = tmp_path / "card.json"
        card.save_json(p)
        data = json.loads(p.read_text())
        assert data["metadata"]["model_name"] == "fraud-detector"

    def test_save_markdown(self, tmp_path):
        card = (ModelCardBuilder()
                .with_metadata(_full_meta())
                .with_risk(self._risk())
                .with_evaluation(self._eval())
                .build())
        p = tmp_path / "card.md"
        card.save_markdown(p)
        md = p.read_text()
        assert "fraud-detector" in md
        assert "EU AI Act" in md
        assert "Evaluation" in md

    def test_markdown_contains_gap_section(self, tmp_path):
        fmt  = EvaluationFormatter()
        ev   = fmt.format([
            MetricResult("f1", 0.95, "ds", slice_name="geo:US"),
            MetricResult("f1", 0.80, "ds", slice_name="geo:EU"),
        ])
        card = (ModelCardBuilder()
                .with_metadata(_full_meta())
                .with_evaluation(ev)
                .build())
        md = card.to_markdown()
        assert "Performance Gaps" in md

    def test_schema_version_set(self):
        card = ModelCardBuilder().with_metadata(_full_meta()).build()
        assert card.version == ModelCardBuilder.SCHEMA_VERSION
