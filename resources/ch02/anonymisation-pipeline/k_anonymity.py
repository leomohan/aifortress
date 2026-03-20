"""
k_anonymity.py  —  k-anonymity and l-diversity enforcement
AI Fortress · Chapter 2 · Code Sample 2.B

k-anonymity (Sweeney 2002): Every record is indistinguishable from at least
  k-1 others with respect to the quasi-identifier attributes.

l-diversity (Machanavajjhala et al. 2007): Every equivalence class contains
  at least l well-represented values of the sensitive attribute, preventing
  homogeneity and background knowledge attacks on k-anonymous datasets.

Implementation strategy:
  1. Group records by quasi-identifiers.
  2. Suppress groups (remove rows) smaller than k.
  3. For l-diversity: suppress equivalence classes with fewer than l distinct
     sensitive values.
  4. Return the filtered DataFrame and an anonymisation report.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
import pandas as pd


@dataclass
class AnonymisationResult:
    original_rows:   int
    remaining_rows:  int
    suppressed_rows: int
    k_achieved:      int      # actual minimum group size achieved
    l_achieved:      Optional[int]  # None if l-diversity not applied
    equivalence_classes: int

    @property
    def suppression_rate(self) -> float:
        return self.suppressed_rows / self.original_rows if self.original_rows else 0.0

    def summary(self) -> str:
        lines = [
            f"k-anonymity result:",
            f"  Original rows      : {self.original_rows}",
            f"  Remaining rows     : {self.remaining_rows}",
            f"  Suppressed rows    : {self.suppressed_rows} ({self.suppression_rate:.1%})",
            f"  k achieved         : {self.k_achieved}",
            f"  Equivalence classes: {self.equivalence_classes}",
        ]
        if self.l_achieved is not None:
            lines.append(f"  l-diversity achieved: {self.l_achieved}")
        return "\n".join(lines)


def enforce_k_anonymity(
    df:                   pd.DataFrame,
    quasi_identifiers:    List[str],
    k:                    int = 5,
) -> tuple[pd.DataFrame, AnonymisationResult]:
    """
    Enforce k-anonymity by suppressing equivalence classes smaller than k.

    Parameters
    ----------
    df                : Input DataFrame
    quasi_identifiers : Columns that, in combination, could re-identify a subject
    k                 : Minimum group size (GDPR guidance: k >= 5; HIPAA Safe Harbour: k >= 20)

    Returns
    -------
    (filtered_df, AnonymisationResult)
    """
    original_rows = len(df)

    # Count group sizes
    group_sizes = df.groupby(quasi_identifiers, observed=True).size().reset_index(name="_size")
    merged = df.merge(group_sizes, on=quasi_identifiers, how="left")

    # Suppress groups below threshold
    mask        = merged["_size"] >= k
    filtered_df = df[mask.values].copy()

    # Compute achieved k (minimum group size in the result)
    if len(filtered_df) == 0:
        k_achieved = 0
    else:
        remaining_groups = filtered_df.groupby(quasi_identifiers, observed=True).size()
        k_achieved = int(remaining_groups.min())

    result = AnonymisationResult(
        original_rows        = original_rows,
        remaining_rows       = len(filtered_df),
        suppressed_rows      = original_rows - len(filtered_df),
        k_achieved           = k_achieved,
        l_achieved           = None,
        equivalence_classes  = filtered_df.groupby(quasi_identifiers, observed=True).ngroups,
    )
    return filtered_df, result


def enforce_l_diversity(
    df:                pd.DataFrame,
    quasi_identifiers: List[str],
    sensitive_attr:    str,
    k:                 int = 5,
    l:                 int = 3,
) -> tuple[pd.DataFrame, AnonymisationResult]:
    """
    Enforce both k-anonymity and l-diversity.

    l-diversity requires each equivalence class to contain at least l distinct
    values of the sensitive attribute, preventing inference even when an attacker
    knows all quasi-identifier values for a target.

    Parameters
    ----------
    sensitive_attr : Column containing the sensitive value (e.g., "diagnosis", "salary_band")
    l              : Minimum distinct sensitive values per equivalence class
    """
    # First apply k-anonymity
    df_k, _ = enforce_k_anonymity(df, quasi_identifiers, k)

    if len(df_k) == 0:
        return df_k, AnonymisationResult(
            original_rows=len(df), remaining_rows=0, suppressed_rows=len(df),
            k_achieved=0, l_achieved=0, equivalence_classes=0,
        )

    # Compute per-group l (number of distinct sensitive values)
    diversity = (
        df_k.groupby(quasi_identifiers, observed=True)[sensitive_attr]
        .nunique()
        .reset_index(name="_l")
    )
    merged    = df_k.merge(diversity, on=quasi_identifiers, how="left")
    mask      = merged["_l"] >= l
    filtered  = df_k[mask.values].copy()

    if len(filtered) == 0:
        l_achieved = 0
        k_achieved = 0
    else:
        grp_sizes  = filtered.groupby(quasi_identifiers, observed=True).size()
        k_achieved = int(grp_sizes.min())
        grp_div    = filtered.groupby(quasi_identifiers, observed=True)[sensitive_attr].nunique()
        l_achieved = int(grp_div.min())

    return filtered, AnonymisationResult(
        original_rows        = len(df),
        remaining_rows       = len(filtered),
        suppressed_rows      = len(df) - len(filtered),
        k_achieved           = k_achieved,
        l_achieved           = l_achieved,
        equivalence_classes  = filtered.groupby(quasi_identifiers, observed=True).ngroups,
    )


def generalise_numeric(
    df:       pd.DataFrame,
    column:   str,
    bin_size: int,
) -> pd.DataFrame:
    """
    Generalise a numeric quasi-identifier into bands.
    E.g. age 37 → "35-39" (bin_size=5), reducing granularity to improve k.
    """
    df = df.copy()
    df[column] = (df[column] // bin_size * bin_size).astype(str) + \
                 "-" + ((df[column] // bin_size + 1) * bin_size - 1).astype(str)
    return df


def truncate_postcode(df: pd.DataFrame, column: str, keep_chars: int = 3) -> pd.DataFrame:
    """Truncate postcodes to the first N characters to reduce granularity."""
    df = df.copy()
    df[column] = df[column].astype(str).str[:keep_chars]
    return df
