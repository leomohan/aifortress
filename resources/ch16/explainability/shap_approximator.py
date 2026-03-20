"""
shap_approximator.py  —  SHAP-style feature importance approximation
AI Fortress · Chapter 16 · Code Sample 16.E

Approximates SHAP (Shapley Additive Explanations) values using
random permutation sampling (the KernelSHAP approximation strategy).

For each feature, the contribution is estimated by comparing the model's
output when the feature is present vs when it is replaced by a baseline
value (mean of that feature across a reference dataset).

True SHAP requires exponential computation; this approximation uses
Monte Carlo sampling of feature coalitions (Lundberg & Lee, 2017).
Production systems should use the official `shap` library.

Reference:
  Lundberg & Lee (2017). "A Unified Approach to Interpreting Model
  Predictions." NeurIPS.
"""
from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


@dataclass
class SHAPExplanation:
    instance:        List[float]
    feature_names:   List[str]
    shap_values:     Dict[str, float]    # feature → SHAP value
    base_value:      float               # mean model output on reference data
    predicted_value: float               # model output for this instance
    top_features:    List[Tuple[str, float]]  # sorted by |SHAP|, descending

    def summary(self) -> str:
        top3 = self.top_features[:3]
        parts = [f"{f}={v:+.3f}" for f, v in top3]
        return (
            f"Prediction={self.predicted_value:.3f} (base={self.base_value:.3f}): "
            + ", ".join(parts)
        )


class SHAPApproximator:
    """
    Approximates SHAP feature importance values.

    Parameters
    ----------
    model_fn       : Callable(List[float]) → float.
    reference_data : List of reference records for baseline computation.
    feature_names  : Names of input features.
    n_samples      : Number of Monte Carlo coalition samples per feature.
    seed           : Random seed.
    """

    def __init__(
        self,
        model_fn:       Callable,
        reference_data: List[List[float]],
        feature_names:  List[str],
        n_samples:      int = 100,
        seed:           int = 42,
    ):
        self._model    = model_fn
        self._ref      = reference_data
        self._names    = feature_names
        self._n        = n_samples
        self._baselines = [
            statistics.mean(row[j] for row in reference_data)
            for j in range(len(feature_names))
        ]
        self._base_value = statistics.mean(self._model(r) for r in reference_data)
        random.seed(seed)

    def explain(self, instance: List[float]) -> SHAPExplanation:
        """Compute approximate SHAP values for a single instance."""
        n_feat = len(self._names)
        shap   = {name: 0.0 for name in self._names}

        for _ in range(self._n):
            # Random coalition (subset of features)
            order    = list(range(n_feat))
            random.shuffle(order)

            for k, feat_idx in enumerate(order):
                # With feature: use instance values for coalition ∪ {feat_idx}
                with_feat    = list(self._baselines)
                without_feat = list(self._baselines)
                for j in order[: k + 1]:
                    with_feat[j] = instance[j]
                for j in order[:k]:
                    without_feat[j] = instance[j]

                marginal = self._model(with_feat) - self._model(without_feat)
                shap[self._names[feat_idx]] += marginal

        # Average over samples
        shap = {k: round(v / self._n, 6) for k, v in shap.items()}
        top  = sorted(shap.items(), key=lambda x: abs(x[1]), reverse=True)
        pred = self._model(instance)

        return SHAPExplanation(
            instance        = list(instance),
            feature_names   = list(self._names),
            shap_values     = shap,
            base_value      = round(self._base_value, 4),
            predicted_value = round(pred, 4),
            top_features    = top,
        )
