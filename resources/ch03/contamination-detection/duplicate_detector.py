"""
duplicate_detector.py  —  Exact hash and MinHash LSH near-duplicate detection
AI Fortress · Chapter 3 · Code Sample 3.A

Duplicate injection is a low-effort poisoning technique: repeating samples
(possibly with minor perturbations) amplifies their influence on model training
without triggering label-flip detectors.

Two detection levels:
  1. Exact duplicates — SHA-256 hash of the serialised row
  2. Near-duplicates  — MinHash + LSH with configurable Jaccard threshold
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from datasketch import MinHash, MinHashLSH


@dataclass
class DuplicateFinding:
    detector:          str = "duplicate"
    severity:          str = "info"
    description:       str = ""
    details:           dict = field(default_factory=dict)


def _row_hash(row: pd.Series, feature_cols: List[str]) -> str:
    payload = json.dumps({c: str(row.get(c, "")) for c in feature_cols}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class DuplicateDetector:
    """
    Detects exact and near-duplicate samples in a training dataset.

    Parameters
    ----------
    jaccard_threshold : Similarity threshold for near-duplicate detection (0-1).
                        0.8 = 80% feature overlap considered near-duplicate.
    num_perm          : Number of MinHash permutations (higher = more accurate, slower)
    max_near_dup_ratio: Fraction above which near-duplicates trigger a warning
    """

    def __init__(
        self,
        jaccard_threshold:    float = 0.8,
        num_perm:             int   = 128,
        max_near_dup_ratio:   float = 0.05,
    ):
        self.jaccard_threshold  = jaccard_threshold
        self.num_perm           = num_perm
        self.max_near_dup_ratio = max_near_dup_ratio

    def detect(
        self,
        df:           pd.DataFrame,
        feature_cols: Optional[List[str]] = None,
        label_col:    Optional[str] = None,
    ) -> List[DuplicateFinding]:
        findings: List[DuplicateFinding] = []
        cols = feature_cols or list(df.columns)

        # ── Exact duplicates ──────────────────────────────────────────────────
        hashes = df.apply(lambda r: _row_hash(r, cols), axis=1)
        dup_mask = hashes.duplicated(keep="first")
        n_exact  = int(dup_mask.sum())
        exact_ratio = n_exact / len(df) if len(df) > 0 else 0.0

        if n_exact > 0:
            severity = "critical" if exact_ratio > 0.1 else "warning"
            findings.append(DuplicateFinding(
                severity    = severity,
                description = (
                    f"{n_exact} exact duplicate rows detected ({exact_ratio:.1%} of dataset). "
                    "Duplicates artificially amplify sample influence during training."
                ),
                details     = {
                    "exact_duplicates": n_exact,
                    "exact_dup_ratio":  round(exact_ratio, 4),
                    "total_rows":       len(df),
                },
            ))

            # Label flip in duplicates: check if any row is duplicated with DIFFERENT labels
            if label_col and label_col in df.columns:
                df_with_hash = df.copy()
                df_with_hash["_hash"] = hashes
                conflicting = (
                    df_with_hash.groupby("_hash")[label_col]
                    .nunique()
                    .gt(1)
                    .sum()
                )
                if conflicting > 0:
                    findings.append(DuplicateFinding(
                        severity    = "critical",
                        description = (
                            f"{conflicting} feature-identical rows have CONFLICTING labels. "
                            "Strong indicator of label-flipping contamination via duplicate injection."
                        ),
                        details     = {"conflicting_hash_groups": int(conflicting)},
                    ))

        # ── Near-duplicates via MinHash LSH ───────────────────────────────────
        near_dup_pairs = self._minhash_near_duplicates(df, cols)
        n_near = len(near_dup_pairs)
        near_ratio = n_near / len(df) if len(df) > 0 else 0.0

        if near_ratio > self.max_near_dup_ratio:
            findings.append(DuplicateFinding(
                severity    = "warning",
                description = (
                    f"{n_near} near-duplicate pairs detected (Jaccard ≥ {self.jaccard_threshold}). "
                    f"Near-duplicate ratio {near_ratio:.1%} exceeds threshold {self.max_near_dup_ratio:.1%}."
                ),
                details     = {
                    "near_dup_pairs":   n_near,
                    "near_dup_ratio":   round(near_ratio, 4),
                    "jaccard_threshold": self.jaccard_threshold,
                    "sample_pairs":     near_dup_pairs[:5],  # first 5 pairs
                },
            ))

        if not any(f.severity in ("warning", "critical") for f in findings):
            findings.append(DuplicateFinding(
                severity    = "info",
                description = f"No significant duplicates detected (exact: {n_exact}, near: {n_near} pairs).",
            ))

        return findings

    def _minhash_near_duplicates(
        self,
        df:   pd.DataFrame,
        cols: List[str],
        max_rows: int = 5000,
    ) -> List[Tuple[int, int]]:
        """Return list of (idx_a, idx_b) near-duplicate pairs."""
        if len(df) > max_rows:
            df = df.sample(max_rows, random_state=42)

        lsh = MinHashLSH(threshold=self.jaccard_threshold, num_perm=self.num_perm)
        minhashes: dict[int, MinHash] = {}

        for idx, row in df.iterrows():
            tokens = set()
            for col in cols:
                val = str(row.get(col, ""))
                # Create shingles: col_name + value quantised to 2 sig figs
                try:
                    tokens.add(f"{col}:{float(val):.2g}")
                except ValueError:
                    tokens.add(f"{col}:{val[:20]}")

            m = MinHash(num_perm=self.num_perm)
            for token in tokens:
                m.update(token.encode("utf-8"))

            key = str(idx)
            lsh.insert(key, m)
            minhashes[idx] = m

        pairs: List[Tuple[int, int]] = []
        seen = set()
        for idx, m in minhashes.items():
            neighbours = lsh.query(m)
            for n_key in neighbours:
                n_idx = int(n_key)
                if n_idx != idx:
                    pair = tuple(sorted([idx, n_idx]))
                    if pair not in seen:
                        seen.add(pair)
                        pairs.append(pair)

        return pairs
