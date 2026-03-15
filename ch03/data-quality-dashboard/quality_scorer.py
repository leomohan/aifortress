"""
quality_scorer.py  —  Composite quality score aggregator
AI Fortress · Chapter 3 · Code Sample 3.C

Aggregates completeness, schema, consistency, and statistical checks into
a single 0-100 quality score with configurable weights and a pass/fail gate.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import numpy as np
import pandas as pd
from completeness_checker import CompletenessResult
from schema_validator import SchemaViolation
from consistency_checker import ConsistencyViolation


@dataclass
class QualityScore:
    score:            float           # 0–100
    passed:           bool
    pass_threshold:   float
    dimension_scores: Dict[str, float]   # completeness, schema, consistency, statistical
    n_errors:         int
    n_warnings:       int
    summary:          str
    details:          dict = field(default_factory=dict)


class QualityScorer:
    """
    Aggregates quality dimensions into a composite score.

    Dimension weights (must sum to 1.0):
      completeness : 0.30
      schema       : 0.30
      consistency  : 0.25
      statistical  : 0.15

    Parameters
    ----------
    pass_threshold : Minimum score to pass quality gate (default 80)
    weights        : Override default dimension weights
    """

    DEFAULT_WEIGHTS = {
        "completeness": 0.30,
        "schema":       0.30,
        "consistency":  0.25,
        "statistical":  0.15,
    }

    def __init__(
        self,
        pass_threshold: float = 80.0,
        weights:        Optional[Dict[str, float]] = None,
    ):
        self.pass_threshold = pass_threshold
        self.weights        = weights or self.DEFAULT_WEIGHTS

    def score(
        self,
        df:                  pd.DataFrame,
        completeness_result: Optional[CompletenessResult]      = None,
        schema_violations:   Optional[List[SchemaViolation]]   = None,
        consistency_violations: Optional[List[ConsistencyViolation]] = None,
    ) -> QualityScore:
        """Compute composite quality score for a DataFrame."""
        dim_scores: Dict[str, float] = {}

        # ── Completeness score ────────────────────────────────────────────
        if completeness_result:
            # Penalise by number of columns exceeding threshold
            n_bad = len(completeness_result.missing_above_threshold)
            n_cols = completeness_result.n_cols or 1
            comp_score = 100.0 * (1 - n_bad / n_cols) * completeness_result.overall_completeness
        else:
            # Compute inline
            comp_score = float(df.notna().values.mean()) * 100
        dim_scores["completeness"] = round(max(0.0, min(100.0, comp_score)), 2)

        # ── Schema score ──────────────────────────────────────────────────
        if schema_violations is not None:
            errors   = sum(v.n_violations for v in schema_violations if v.severity == "error" and v.n_violations > 0)
            n_cells  = len(df) * len(df.columns) if len(df) > 0 else 1
            schema_score = max(0.0, 100.0 * (1 - errors / max(n_cells, 1)))
        else:
            schema_score = 100.0
        dim_scores["schema"] = round(schema_score, 2)

        # ── Consistency score ─────────────────────────────────────────────
        if consistency_violations is not None:
            total_violation_rate = sum(
                v.violation_rate for v in consistency_violations
                if v.violation_rate > 0
            )
            n_constraints = max(len(consistency_violations), 1)
            consistency_score = max(0.0, 100.0 * (1 - total_violation_rate / n_constraints))
        else:
            consistency_score = 100.0
        dim_scores["consistency"] = round(consistency_score, 2)

        # ── Statistical score (basic checks inline) ───────────────────────
        stat_score = self._statistical_score(df)
        dim_scores["statistical"] = round(stat_score, 2)

        # ── Composite weighted score ──────────────────────────────────────
        composite = sum(
            dim_scores.get(dim, 100.0) * w
            for dim, w in self.weights.items()
        )
        composite = round(max(0.0, min(100.0, composite)), 2)

        # Count errors and warnings
        all_violations = list(schema_violations or []) + list(consistency_violations or [])
        n_errors   = sum(1 for v in all_violations if v.severity == "error")
        n_warnings = sum(1 for v in all_violations if v.severity == "warning")
        if completeness_result and completeness_result.missing_above_threshold:
            n_warnings += len(completeness_result.missing_above_threshold)

        passed  = composite >= self.pass_threshold
        summary = (
            f"Quality score: {composite}/100 — {'✅ PASS' if passed else '❌ FAIL'} "
            f"(threshold {self.pass_threshold}) | "
            f"Errors: {n_errors} | Warnings: {n_warnings}"
        )

        return QualityScore(
            score            = composite,
            passed           = passed,
            pass_threshold   = self.pass_threshold,
            dimension_scores = dim_scores,
            n_errors         = n_errors,
            n_warnings       = n_warnings,
            summary          = summary,
            details          = {"weights": self.weights},
        )

    def _statistical_score(self, df: pd.DataFrame) -> float:
        """Basic statistical checks: constant columns, inf values, extreme skew."""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) == 0:
            return 100.0

        penalties = 0.0
        for col in numeric_cols:
            series = df[col].dropna()
            if len(series) == 0:
                continue
            # Constant column
            if series.nunique() == 1:
                penalties += 10.0
            # Infinite values
            if np.isinf(series.values).any():
                penalties += 15.0
            # Extreme skew (|skew| > 10)
            try:
                skew = float(series.skew())
                if abs(skew) > 10:
                    penalties += 5.0
            except Exception:
                pass

        max_penalty = len(numeric_cols) * 30.0
        return max(0.0, 100.0 - (penalties / max_penalty * 100)) if max_penalty > 0 else 100.0
