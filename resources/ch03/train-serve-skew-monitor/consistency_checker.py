"""
consistency_checker.py  —  Cross-column constraint and referential integrity checks
AI Fortress · Chapter 3 · Code Sample 3.C
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
import pandas as pd


@dataclass
class ConsistencyConstraint:
    name:        str
    description: str
    check_fn:    Callable[[pd.DataFrame], pd.Series]   # returns boolean mask of valid rows
    severity:    str = "error"   # "error" | "warning"


@dataclass
class ConsistencyViolation:
    constraint:    str
    severity:      str
    n_violations:  int
    violation_rate: float
    description:   str
    sample_indices: List[int] = field(default_factory=list)


class ConsistencyChecker:
    """
    Runs a set of cross-column constraints and reports violations.

    Parameters
    ----------
    constraints : List of ConsistencyConstraint objects.
                  Each constraint's check_fn receives the full DataFrame and
                  must return a boolean Series (True = valid, False = violation).
    """

    def __init__(self, constraints: Optional[List[ConsistencyConstraint]] = None):
        self.constraints = constraints or []

    def add(self, constraint: ConsistencyConstraint) -> None:
        self.constraints.append(constraint)

    def check(self, df: pd.DataFrame) -> List[ConsistencyViolation]:
        violations: List[ConsistencyViolation] = []
        for c in self.constraints:
            try:
                valid_mask    = c.check_fn(df)
                n_invalid     = int((~valid_mask).sum())
                if n_invalid > 0:
                    bad_idx = df.index[~valid_mask].tolist()[:5]
                    violations.append(ConsistencyViolation(
                        constraint    = c.name,
                        severity      = c.severity,
                        n_violations  = n_invalid,
                        violation_rate = round(n_invalid / len(df), 4),
                        description   = c.description,
                        sample_indices = [int(i) for i in bad_idx],
                    ))
            except Exception as e:
                violations.append(ConsistencyViolation(
                    constraint   = c.name,
                    severity     = "error",
                    n_violations = -1,
                    violation_rate = -1.0,
                    description  = f"Constraint check '{c.name}' raised: {e}",
                ))

        # ── Built-in: duplicate primary key detection ─────────────────────
        return violations

    def check_duplicates(self, df: pd.DataFrame, key_cols: List[str]) -> ConsistencyViolation | None:
        """Check for duplicate primary keys."""
        dupes = df.duplicated(subset=key_cols, keep="first").sum()
        if dupes > 0:
            return ConsistencyViolation(
                constraint    = "primary_key_unique",
                severity      = "error",
                n_violations  = int(dupes),
                violation_rate = round(int(dupes) / len(df), 4),
                description   = f"Duplicate rows on key columns {key_cols}: {dupes} duplicates.",
            )
        return None


# ── Pre-built constraint factory functions ────────────────────────────────────

def date_order_constraint(start_col: str, end_col: str) -> ConsistencyConstraint:
    return ConsistencyConstraint(
        name        = f"{start_col}_before_{end_col}",
        description = f"'{start_col}' must be <= '{end_col}'",
        check_fn    = lambda df: pd.to_datetime(df[start_col]) <= pd.to_datetime(df[end_col]),
    )


def positive_constraint(col: str) -> ConsistencyConstraint:
    return ConsistencyConstraint(
        name        = f"{col}_positive",
        description = f"'{col}' must be > 0",
        check_fn    = lambda df: pd.to_numeric(df[col], errors="coerce").gt(0),
    )


def referential_integrity_constraint(
    fk_col: str,
    reference_values: List,
) -> ConsistencyConstraint:
    ref_set = set(reference_values)
    return ConsistencyConstraint(
        name        = f"{fk_col}_referential_integrity",
        description = f"'{fk_col}' must only contain values from the reference set",
        check_fn    = lambda df: df[fk_col].isin(ref_set),
        severity    = "error",
    )
