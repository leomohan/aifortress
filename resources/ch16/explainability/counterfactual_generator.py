"""
counterfactual_generator.py  —  Counterfactual explanation generator
AI Fortress · Chapter 16 · Code Sample 16.E

Generates counterfactual explanations: the minimal feature change
needed to flip the model's prediction to a desired outcome.

"What would need to change for this loan application to be approved?"

Algorithm: greedy hill-climbing over feature space.
  1. Start from the original instance.
  2. At each step, perturb the feature that most reduces distance to target output.
  3. Stop when the target prediction is reached or max iterations exceeded.

For immutable features (e.g. race, gender): lock them and only perturb
the actionable features.

Reference:
  Wachter, Mittelstadt & Russell (2017). "Counterfactual Explanations
  Without Opening the Black Box." Harvard JOLT.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple


@dataclass
class Counterfactual:
    original:         List[float]
    counterfactual:   List[float]
    changed_features: Dict[str, Tuple[float, float]]  # name → (original, new)
    original_pred:    float
    cf_pred:          float
    target_pred:      float
    n_changes:        int
    found:            bool
    detail:           str


class CounterfactualGenerator:
    """
    Generates counterfactual explanations via greedy hill-climbing.

    Parameters
    ----------
    model_fn         : Callable(List[float]) → float (predicted probability).
    feature_names    : Names of features.
    feature_ranges   : Dict of feature name → (min, max) for perturbation.
    immutable_features: Set of feature names that cannot be changed.
    step_size        : Perturbation step size (fraction of feature range).
    max_iterations   : Maximum hill-climbing steps.
    """

    def __init__(
        self,
        model_fn:            Callable,
        feature_names:       List[str],
        feature_ranges:      Dict[str, Tuple[float, float]],
        immutable_features:  Optional[Set[str]] = None,
        step_size:           float = 0.05,
        max_iterations:      int   = 200,
    ):
        self._model     = model_fn
        self._names     = feature_names
        self._ranges    = feature_ranges
        self._immutable = immutable_features or set()
        self._step      = step_size
        self._max_iter  = max_iterations

    def generate(
        self,
        instance:     List[float],
        target_pred:  float = 0.5,   # flip threshold
    ) -> Counterfactual:
        """
        Generate a counterfactual for instance such that model output ≥ target_pred.

        Parameters
        ----------
        instance    : Original feature vector.
        target_pred : Desired model output (default 0.5 = flip to positive class).
        """
        current     = list(instance)
        orig_pred   = self._model(instance)
        found       = False

        if orig_pred >= target_pred:
            # Already meets target; return trivial counterfactual
            return Counterfactual(
                original=instance, counterfactual=current,
                changed_features={}, original_pred=round(orig_pred, 4),
                cf_pred=round(orig_pred, 4), target_pred=target_pred,
                n_changes=0, found=True,
                detail="Original prediction already meets target.",
            )

        for _ in range(self._max_iter):
            best_delta, best_idx, best_direction = 0.0, -1, 0

            for i, name in enumerate(self._names):
                if name in self._immutable:
                    continue
                lo, hi = self._ranges.get(name, (0.0, 1.0))
                rng    = hi - lo
                step   = rng * self._step

                for direction in [1, -1]:
                    cand     = list(current)
                    new_val  = cand[i] + direction * step
                    cand[i]  = max(lo, min(hi, new_val))
                    delta    = self._model(cand) - self._model(current)
                    if delta > best_delta:
                        best_delta, best_idx, best_direction = delta, i, direction

            if best_idx == -1:
                break   # no improving move found

            lo, hi = self._ranges.get(self._names[best_idx], (0.0, 1.0))
            rng    = hi - lo
            current[best_idx] = max(lo, min(hi, current[best_idx] + best_direction * rng * self._step))

            if self._model(current) >= target_pred:
                found = True
                break

        cf_pred   = self._model(current)
        changed   = {}
        for i, name in enumerate(self._names):
            if abs(current[i] - instance[i]) > 1e-9:
                changed[name] = (round(instance[i], 4), round(current[i], 4))

        return Counterfactual(
            original        = list(instance),
            counterfactual  = current,
            changed_features = changed,
            original_pred   = round(orig_pred, 4),
            cf_pred         = round(cf_pred, 4),
            target_pred     = target_pred,
            n_changes       = len(changed),
            found           = found,
            detail          = (
                f"Counterfactual found: {len(changed)} feature(s) changed." if found
                else "No counterfactual found within iteration limit."
            ),
        )
