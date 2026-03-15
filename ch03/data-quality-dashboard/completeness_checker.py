"""
completeness_checker.py  —  Missing-value analysis
AI Fortress · Chapter 3 · Code Sample 3.C
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import pandas as pd


@dataclass
class CompletenessResult:
    overall_completeness: float           # fraction of non-null cells
    column_completeness:  Dict[str, float]  # col → fraction non-null
    missing_above_threshold: List[str]    # cols exceeding missingness budget
    row_completeness:     float           # fraction of fully-complete rows
    n_rows:               int
    n_cols:               int
    threshold:            float


class CompletenessChecker:
    """
    Measures missing-value rates and flags columns/rows exceeding thresholds.

    Parameters
    ----------
    col_threshold  : Max allowed missing fraction per column (default 0.05 = 5%)
    row_threshold  : Min fraction of rows that must be fully complete (default 0.90)
    """

    def __init__(self, col_threshold: float = 0.05, row_threshold: float = 0.90):
        self.col_threshold = col_threshold
        self.row_threshold = row_threshold

    def check(
        self,
        df:      pd.DataFrame,
        columns: Optional[List[str]] = None,
    ) -> CompletenessResult:
        cols = columns or list(df.columns)
        sub  = df[cols]

        col_completeness = {
            col: round(float(1 - sub[col].isna().mean()), 4)
            for col in cols
        }
        missing_above = [
            col for col, comp in col_completeness.items()
            if (1 - comp) > self.col_threshold
        ]
        overall     = round(float(sub.notna().values.mean()), 4)
        row_comp    = round(float(sub.notna().all(axis=1).mean()), 4)

        return CompletenessResult(
            overall_completeness   = overall,
            column_completeness    = col_completeness,
            missing_above_threshold = missing_above,
            row_completeness       = row_comp,
            n_rows                 = len(df),
            n_cols                 = len(cols),
            threshold              = self.col_threshold,
        )
