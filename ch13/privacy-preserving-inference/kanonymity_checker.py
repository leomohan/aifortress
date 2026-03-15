"""
kanonymity_checker.py  —  k-anonymity response checker for ML inference
AI Fortress · Chapter 13 · Code Sample 13.E

Verifies that a prediction response satisfies k-anonymity: the
predicted class must be assigned to at least k records in a reference
dataset that share the same quasi-identifier feature values.

If a prediction is unique (k < threshold), it is suppressed or
generalised before being returned to the caller.

Based on the k-anonymity model of Sweeney (2002).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class KAnonCheckResult:
    satisfies_k_anon: bool
    k_value:          int          # actual k found for this quasi-id group
    k_threshold:      int
    predicted_class:  int
    suppressed:       bool         # True if response was suppressed
    generalised:      bool         # True if quasi-ids were generalised
    detail:           str


class KAnonymityChecker:
    """
    Checks and enforces k-anonymity on inference responses.

    Parameters
    ----------
    k               : Minimum equivalence class size required.
    quasi_id_cols   : Names of quasi-identifier columns.
    reference_data  : List of dicts representing the reference dataset.
                      Used to compute equivalence class sizes.
    suppress_below_k: If True, suppress predictions with k < threshold.
                      If False, generalise by returning None for confidence.
    """

    def __init__(
        self,
        k:              int,
        quasi_id_cols:  List[str],
        reference_data: List[Dict[str, Any]],
        suppress_below_k: bool = True,
    ):
        if k < 1:
            raise ValueError("k must be ≥ 1")
        self._k         = k
        self._qi_cols   = quasi_id_cols
        self._suppress  = suppress_below_k
        self._index     = self._build_index(reference_data)

    def check(
        self,
        query_record:    Dict[str, Any],
        predicted_class: int,
    ) -> KAnonCheckResult:
        """
        Check whether the query record satisfies k-anonymity.

        Parameters
        ----------
        query_record    : Feature dict for the record being predicted.
        predicted_class : Model's predicted class label.
        """
        qi_key   = self._qi_key(query_record)
        eq_size  = self._index.get(qi_key, 0)
        satisfies = eq_size >= self._k

        return KAnonCheckResult(
            satisfies_k_anon = satisfies,
            k_value          = eq_size,
            k_threshold      = self._k,
            predicted_class  = predicted_class if satisfies else -1,
            suppressed       = (not satisfies) and self._suppress,
            generalised      = (not satisfies) and (not self._suppress),
            detail           = (
                f"Equivalence class size={eq_size} for qi_key='{qi_key}'. "
                + ("Satisfies k-anonymity." if satisfies
                   else f"Below threshold k={self._k}; response {'suppressed' if self._suppress else 'generalised'}.")
            ),
        )

    def equivalence_class_size(self, query_record: Dict[str, Any]) -> int:
        return self._index.get(self._qi_key(query_record), 0)

    def _qi_key(self, record: Dict[str, Any]) -> str:
        return "|".join(
            f"{col}={record.get(col, '')}" for col in sorted(self._qi_cols)
        )

    def _build_index(self, data: List[Dict[str, Any]]) -> Dict[str, int]:
        idx: Dict[str, int] = {}
        for rec in data:
            key = self._qi_key(rec)
            idx[key] = idx.get(key, 0) + 1
        return idx
