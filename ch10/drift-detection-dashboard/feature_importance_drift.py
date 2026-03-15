"""
feature_importance_drift.py  —  Feature importance drift and rank inversion detection
AI Fortress · Chapter 10 · Code Sample 10.A

Compares SHAP-style feature importance rankings between a baseline
(captured at deployment) and a current production window.

Signals detected:
  RANK_INVERSION  — two features swap rank relative to baseline
                    (top-K inversions trigger alert)
  MAGNITUDE_SHIFT — feature importance magnitude changes by more than
                    a configurable threshold (fraction of baseline value)
  NEW_TOP_FEATURE — a feature not in the baseline top-K enters top-K
                    (may indicate adversarial feature manipulation)
  IMPORTANCE_COLLAPSE — a previously important feature drops near zero

Spearman rank correlation is computed for a single continuous score.
A correlation < 0.7 triggers a WARNING; < 0.4 triggers CRITICAL.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy import stats


@dataclass
class ImportanceDriftSignal:
    signal:   str        # "rank_inversion" | "magnitude_shift" | etc.
    severity: str        # "WARNING" | "CRITICAL"
    feature:  str
    detail:   str


@dataclass
class ImportanceDriftResult:
    status:           str         # "OK" | "WARNING" | "CRITICAL"
    spearman_corr:    float
    signals:          List[ImportanceDriftSignal]
    top_k_overlap:    float       # fraction of baseline top-K still in current top-K
    detail:           str

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class FeatureImportanceDrift:
    """
    Detects drift in feature importance rankings.

    Parameters
    ----------
    top_k             : Number of top features to track for rank analysis.
    magnitude_thresh  : Fraction change in importance to trigger alert (default 0.5 = 50%).
    corr_warning      : Spearman correlation below this → WARNING.
    corr_critical     : Spearman correlation below this → CRITICAL.
    collapse_thresh   : Importance magnitude below this fraction of baseline → collapse alert.
    """

    def __init__(
        self,
        top_k:            int   = 10,
        magnitude_thresh: float = 0.5,
        corr_warning:     float = 0.7,
        corr_critical:    float = 0.4,
        collapse_thresh:  float = 0.1,
    ):
        self.top_k         = top_k
        self.mag_thresh    = magnitude_thresh
        self.corr_warn     = corr_warning
        self.corr_crit     = corr_critical
        self.collapse_thr  = collapse_thresh

    def check(
        self,
        baseline:  Dict[str, float],   # feature → importance score
        current:   Dict[str, float],
    ) -> ImportanceDriftResult:
        """
        Compare current feature importances to baseline.

        Parameters
        ----------
        baseline : Dict of feature_name → importance score at deployment
        current  : Dict of feature_name → importance score in current window
        """
        signals: List[ImportanceDriftSignal] = []
        common  = sorted(set(baseline) & set(current))

        if len(common) < 2:
            return ImportanceDriftResult(
                status="OK", spearman_corr=1.0, signals=[],
                top_k_overlap=1.0, detail="Insufficient common features",
            )

        base_arr = np.array([baseline[f] for f in common])
        curr_arr = np.array([current[f]  for f in common])

        # Spearman rank correlation
        corr, _ = stats.spearmanr(base_arr, curr_arr)
        corr     = float(corr) if not np.isnan(corr) else 0.0

        # Top-K overlap
        base_top = set(sorted(baseline, key=baseline.get, reverse=True)[:self.top_k])
        curr_top = set(sorted(current,  key=current.get,  reverse=True)[:self.top_k])
        overlap  = len(base_top & curr_top) / max(len(base_top), 1)

        # New top-K features
        new_top = curr_top - base_top
        for feat in new_top:
            signals.append(ImportanceDriftSignal(
                signal   = "new_top_feature",
                severity = "WARNING",
                feature  = feat,
                detail   = f"'{feat}' entered top-{self.top_k} but was not in baseline top-{self.top_k}",
            ))

        # Magnitude shifts and collapses
        base_total = max(sum(abs(v) for v in baseline.values()), 1e-9)
        curr_total = max(sum(abs(v) for v in current.values()),  1e-9)

        for feat in common:
            base_norm = abs(baseline[feat]) / base_total
            curr_norm = abs(current[feat])  / curr_total

            if base_norm > 0:
                change = abs(curr_norm - base_norm) / base_norm
                if change > self.mag_thresh:
                    signals.append(ImportanceDriftSignal(
                        signal   = "magnitude_shift",
                        severity = "WARNING",
                        feature  = feat,
                        detail   = f"Importance magnitude changed by {change:.1%} for '{feat}'",
                    ))

            if base_norm > self.collapse_thresh and curr_norm < base_norm * self.collapse_thresh:
                signals.append(ImportanceDriftSignal(
                    signal   = "importance_collapse",
                    severity = "CRITICAL",
                    feature  = feat,
                    detail   = (f"'{feat}' importance collapsed: "
                                f"baseline={base_norm:.4f}, current={curr_norm:.4f}"),
                ))

        # Rank inversions among top-K
        base_ranks = {f: i for i, f in enumerate(
            sorted(baseline, key=baseline.get, reverse=True))}
        curr_ranks = {f: i for i, f in enumerate(
            sorted(current,  key=current.get,  reverse=True))}

        inversions = 0
        top_features = list(base_top)[:min(self.top_k, len(base_top))]
        for i in range(len(top_features)):
            for j in range(i + 1, len(top_features)):
                fa, fb = top_features[i], top_features[j]
                if fb in curr_ranks and fa in curr_ranks:
                    # Baseline: fa ranks higher than fb; current: fb ranks higher
                    if curr_ranks[fa] > curr_ranks[fb]:
                        inversions += 1

        if inversions > max(1, self.top_k // 3):
            signals.append(ImportanceDriftSignal(
                signal   = "rank_inversion",
                severity = "WARNING" if inversions < self.top_k // 2 else "CRITICAL",
                feature  = "top-k",
                detail   = f"{inversions} rank inversions detected in top-{self.top_k} features",
            ))

        # Overall status
        if corr < self.corr_crit or any(s.severity == "CRITICAL" for s in signals):
            status = "CRITICAL"
        elif corr < self.corr_warn or signals:
            status = "WARNING"
        else:
            status = "OK"

        return ImportanceDriftResult(
            status        = status,
            spearman_corr = round(corr, 4),
            signals       = signals,
            top_k_overlap = round(overlap, 4),
            detail        = (f"Spearman r={corr:.4f}, top-{self.top_k} overlap={overlap:.1%}, "
                             f"{len(signals)} signal(s)"),
        )
