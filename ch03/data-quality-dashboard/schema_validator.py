"""
schema_validator.py  —  Schema enforcement and violation reporting
AI Fortress · Chapter 3 · Code Sample 3.C

Validates a DataFrame against a declared schema. Reports violations with
severity levels (error / warning / info) suitable for CI/CD pipeline gates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Set

import numpy as np
import pandas as pd


@dataclass
class ColumnSpec:
    name:            str
    dtype:           str                   # "numeric" | "string" | "categorical" | "boolean" | "datetime"
    nullable:        bool = True
    min_val:         Optional[float] = None
    max_val:         Optional[float] = None
    min_length:      Optional[int] = None   # for strings
    max_length:      Optional[int] = None
    allowed_values:  Optional[List[Any]] = None
    max_cardinality: Optional[int] = None   # max distinct values (for categoricals)
    regex_pattern:   Optional[str] = None   # for string validation


@dataclass
class SchemaViolation:
    column:    str
    rule:      str
    severity:  str       # "error" | "warning"
    n_violations: int
    description: str
    sample_values: List[Any] = field(default_factory=list)


class SchemaValidator:
    """
    Validates a DataFrame against a list of ColumnSpec definitions.

    Parameters
    ----------
    specs            : List of column specifications
    extra_cols_error : Raise error (not just warning) for unexpected columns
    """

    def __init__(
        self,
        specs:             List[ColumnSpec],
        extra_cols_error:  bool = False,
    ):
        self.specs           = {s.name: s for s in specs}
        self.extra_cols_error = extra_cols_error

    def validate(self, df: pd.DataFrame) -> List[SchemaViolation]:
        violations: List[SchemaViolation] = []

        # ── Missing required columns ───────────────────────────────────────
        for col_name, spec in self.specs.items():
            if col_name not in df.columns:
                violations.append(SchemaViolation(
                    column=col_name, rule="column_present", severity="error",
                    n_violations=1,
                    description=f"Required column '{col_name}' is missing from DataFrame.",
                ))
                continue

            col = df[col_name]

            # ── Nullability ──────────────────────────────────────────────
            n_null = int(col.isna().sum())
            if not spec.nullable and n_null > 0:
                violations.append(SchemaViolation(
                    column=col_name, rule="not_nullable", severity="error",
                    n_violations=n_null,
                    description=f"Column '{col_name}' has {n_null} null values but is declared non-nullable.",
                ))

            # ── Dtype checks ─────────────────────────────────────────────
            if spec.dtype == "numeric":
                non_numeric = col.dropna()
                try:
                    non_numeric = pd.to_numeric(non_numeric, errors="coerce")
                    bad = int(non_numeric.isna().sum())
                    if bad > 0:
                        violations.append(SchemaViolation(
                            column=col_name, rule="dtype_numeric", severity="error",
                            n_violations=bad,
                            description=f"Column '{col_name}' has {bad} non-numeric values.",
                        ))
                except Exception:
                    pass

            elif spec.dtype == "boolean":
                valid_bool = {True, False, 0, 1, "true", "false", "True", "False", "0", "1"}
                bad_mask = col.dropna().apply(lambda v: v not in valid_bool)
                if bad_mask.sum() > 0:
                    violations.append(SchemaViolation(
                        column=col_name, rule="dtype_boolean", severity="error",
                        n_violations=int(bad_mask.sum()),
                        description=f"Column '{col_name}' has non-boolean values.",
                        sample_values=col.dropna()[bad_mask].head(3).tolist(),
                    ))

            # ── Range checks ─────────────────────────────────────────────
            if spec.min_val is not None or spec.max_val is not None:
                numeric_col = pd.to_numeric(col, errors="coerce").dropna()
                if spec.min_val is not None:
                    below = int((numeric_col < spec.min_val).sum())
                    if below > 0:
                        violations.append(SchemaViolation(
                            column=col_name, rule="min_val", severity="error",
                            n_violations=below,
                            description=f"Column '{col_name}' has {below} values below min={spec.min_val}.",
                            sample_values=numeric_col[numeric_col < spec.min_val].head(3).tolist(),
                        ))
                if spec.max_val is not None:
                    above = int((numeric_col > spec.max_val).sum())
                    if above > 0:
                        violations.append(SchemaViolation(
                            column=col_name, rule="max_val", severity="error",
                            n_violations=above,
                            description=f"Column '{col_name}' has {above} values above max={spec.max_val}.",
                            sample_values=numeric_col[numeric_col > spec.max_val].head(3).tolist(),
                        ))

            # ── Allowed values ────────────────────────────────────────────
            if spec.allowed_values is not None:
                allowed: Set[Any] = set(spec.allowed_values)
                bad_mask = col.dropna().apply(lambda v: v not in allowed)
                if bad_mask.sum() > 0:
                    violations.append(SchemaViolation(
                        column=col_name, rule="allowed_values", severity="error",
                        n_violations=int(bad_mask.sum()),
                        description=(
                            f"Column '{col_name}' has {bad_mask.sum()} values outside "
                            f"allowed set {spec.allowed_values}."
                        ),
                        sample_values=col.dropna()[bad_mask].head(3).tolist(),
                    ))

            # ── Cardinality ───────────────────────────────────────────────
            if spec.max_cardinality is not None:
                n_unique = col.nunique()
                if n_unique > spec.max_cardinality:
                    violations.append(SchemaViolation(
                        column=col_name, rule="max_cardinality", severity="warning",
                        n_violations=1,
                        description=(
                            f"Column '{col_name}' has {n_unique} distinct values "
                            f"(max allowed: {spec.max_cardinality})."
                        ),
                    ))

            # ── String length ─────────────────────────────────────────────
            if spec.dtype == "string" and (spec.min_length or spec.max_length):
                str_col = col.dropna().astype(str)
                lengths = str_col.str.len()
                if spec.min_length and (lengths < spec.min_length).sum() > 0:
                    n = int((lengths < spec.min_length).sum())
                    violations.append(SchemaViolation(
                        column=col_name, rule="min_length", severity="warning",
                        n_violations=n,
                        description=f"Column '{col_name}' has {n} strings shorter than {spec.min_length}.",
                    ))
                if spec.max_length and (lengths > spec.max_length).sum() > 0:
                    n = int((lengths > spec.max_length).sum())
                    violations.append(SchemaViolation(
                        column=col_name, rule="max_length", severity="error",
                        n_violations=n,
                        description=f"Column '{col_name}' has {n} strings longer than {spec.max_length}.",
                    ))

        # ── Unexpected columns ────────────────────────────────────────────
        extra = set(df.columns) - set(self.specs.keys())
        if extra:
            violations.append(SchemaViolation(
                column="*", rule="unexpected_columns",
                severity="error" if self.extra_cols_error else "warning",
                n_violations=len(extra),
                description=f"Unexpected columns found: {sorted(extra)}",
            ))

        return violations
