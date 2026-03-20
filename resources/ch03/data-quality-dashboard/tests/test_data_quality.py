"""
tests/test_data_quality.py  —  Data quality dashboard tests
AI Fortress · Chapter 3 · Code Sample 3.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import numpy as np
import pandas as pd
import pytest
from schema_validator import SchemaValidator, ColumnSpec
from completeness_checker import CompletenessChecker
from consistency_checker import (
    ConsistencyChecker, ConsistencyConstraint,
    date_order_constraint, positive_constraint, referential_integrity_constraint,
)
from quality_scorer import QualityScorer
from pipeline_monitor import PipelineMonitor


def _good_df():
    return pd.DataFrame({
        "age":   [25, 34, 45, 28, 52],
        "email": ["a@b.com","c@d.com","e@f.com","g@h.com","i@j.com"],
        "label": ["cat","dog","cat","dog","cat"],
        "score": [0.8, 0.6, 0.9, 0.7, 0.5],
    })


class TestSchemaValidator:
    def test_valid_df_no_violations(self):
        df    = _good_df()
        specs = [
            ColumnSpec("age",   dtype="numeric", min_val=0, max_val=120),
            ColumnSpec("email", dtype="string"),
            ColumnSpec("label", dtype="categorical", allowed_values=["cat","dog"]),
            ColumnSpec("score", dtype="numeric", min_val=0.0, max_val=1.0),
        ]
        violations = SchemaValidator(specs).validate(df)
        errors = [v for v in violations if v.severity == "error"]
        assert len(errors) == 0

    def test_missing_column(self):
        df    = _good_df().drop(columns=["age"])
        specs = [ColumnSpec("age", dtype="numeric")]
        violations = SchemaValidator(specs).validate(df)
        assert any(v.rule == "column_present" for v in violations)

    def test_out_of_range(self):
        df = _good_df().copy()
        df.loc[0, "age"] = 999   # too high
        specs = [ColumnSpec("age", dtype="numeric", min_val=0, max_val=120)]
        violations = SchemaValidator(specs).validate(df)
        assert any(v.rule == "max_val" for v in violations)

    def test_invalid_category(self):
        df = _good_df().copy()
        df.loc[0, "label"] = "fish"
        specs = [ColumnSpec("label", dtype="categorical", allowed_values=["cat","dog"])]
        violations = SchemaValidator(specs).validate(df)
        assert any(v.rule == "allowed_values" for v in violations)

    def test_not_nullable_with_nulls(self):
        df = _good_df().copy()
        df.loc[0, "email"] = None
        specs = [ColumnSpec("email", dtype="string", nullable=False)]
        violations = SchemaValidator(specs).validate(df)
        assert any(v.rule == "not_nullable" for v in violations)


class TestCompletenessChecker:
    def test_complete_df(self):
        df     = _good_df()
        result = CompletenessChecker(col_threshold=0.05).check(df)
        assert result.overall_completeness == 1.0
        assert result.missing_above_threshold == []

    def test_missing_values_flagged(self):
        df = _good_df().copy()
        df.loc[[0,1,2], "age"] = None   # 60% missing
        result = CompletenessChecker(col_threshold=0.05).check(df)
        assert "age" in result.missing_above_threshold

    def test_row_completeness(self):
        df = _good_df().copy()
        df.loc[0, "age"] = None
        result = CompletenessChecker().check(df)
        assert result.row_completeness < 1.0


class TestConsistencyChecker:
    def test_valid_constraints_no_violations(self):
        df = pd.DataFrame({
            "start": ["2024-01-01","2024-02-01"],
            "end":   ["2024-06-01","2024-12-01"],
            "price": [10.0, 20.0],
        })
        checker = ConsistencyChecker([
            date_order_constraint("start", "end"),
            positive_constraint("price"),
        ])
        violations = checker.check(df)
        assert len(violations) == 0

    def test_date_order_violation(self):
        df = pd.DataFrame({
            "start": ["2024-12-01","2024-02-01"],
            "end":   ["2024-01-01","2024-12-01"],   # row 0: end before start
        })
        checker = ConsistencyChecker([date_order_constraint("start","end")])
        violations = checker.check(df)
        assert violations[0].n_violations == 1

    def test_referential_integrity(self):
        df = pd.DataFrame({"cat_id": [1, 2, 99]})  # 99 not in reference
        checker = ConsistencyChecker([
            referential_integrity_constraint("cat_id", [1, 2, 3])
        ])
        violations = checker.check(df)
        assert violations[0].n_violations == 1

    def test_duplicate_key_detection(self):
        df = pd.DataFrame({"id": [1, 2, 1], "val": ["a","b","c"]})
        checker = ConsistencyChecker()
        viol = checker.check_duplicates(df, ["id"])
        assert viol is not None
        assert viol.n_violations == 1


class TestQualityScorer:
    def test_perfect_score(self):
        df    = _good_df()
        score = QualityScorer(pass_threshold=70).score(df)
        assert score.score > 70
        assert score.passed

    def test_score_drops_with_violations(self):
        df_good = _good_df()
        df_bad  = df_good.copy()
        df_bad.loc[:, "age"] = None   # all nulls
        score_good = QualityScorer().score(df_good)
        score_bad  = QualityScorer().score(df_bad)
        assert score_bad.score < score_good.score

    def test_fail_below_threshold(self):
        df = pd.DataFrame({"x": [None]*100})
        score = QualityScorer(pass_threshold=90).score(df)
        assert not score.passed


class TestPipelineMonitor:
    def test_regression_detected(self):
        monitor = PipelineMonitor(regression_threshold=5.0)
        scorer  = QualityScorer(pass_threshold=50)

        df_good = _good_df()
        df_bad  = pd.DataFrame({"age": [None]*5, "email": [None]*5,
                                 "label": [None]*5, "score": [None]*5})

        monitor.record("raw",     scorer.score(df_good))
        monitor.record("cleaned", scorer.score(df_bad))

        regressions = monitor.detect_regressions()
        assert len(regressions) > 0
        assert any(r.from_stage == "raw" for r in regressions)

    def test_no_regression_stable_quality(self):
        monitor = PipelineMonitor(regression_threshold=5.0)
        scorer  = QualityScorer()
        df = _good_df()
        monitor.record("raw",     scorer.score(df))
        monitor.record("cleaned", scorer.score(df))
        regressions = monitor.detect_regressions()
        assert len(regressions) == 0

    def test_report_serialisable(self, tmp_path):
        import json
        monitor = PipelineMonitor()
        scorer  = QualityScorer()
        monitor.record("raw", scorer.score(_good_df()))
        monitor.save_report(tmp_path / "quality_report.json")
        data = json.loads((tmp_path / "quality_report.json").read_text())
        assert len(data["stages"]) == 1
