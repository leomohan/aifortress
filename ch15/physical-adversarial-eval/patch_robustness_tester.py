"""
patch_robustness_tester.py  —  Physical adversarial patch robustness evaluation
AI Fortress · Chapter 15 · Code Sample 15.E

Evaluates the robustness of an edge CV model against physical adversarial
patches. A "patch" is a region of the input that has been modified to
cause misclassification (printed sticker, projected pattern, etc.).

This module simulates the patch attack by replacing a configurable
rectangular region of the input feature vector with adversarial values,
then measures the accuracy drop vs clean inputs.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


@dataclass
class PatchAttackConfig:
    patch_fraction: float = 0.10    # fraction of input dimensions replaced
    n_trials:       int   = 100     # number of test samples
    patch_value:    Optional[float] = None  # fixed adversarial value; None = random


@dataclass
class PatchRobustnessResult:
    clean_accuracy:   float
    patched_accuracy: float
    accuracy_drop:    float
    attack_success_rate: float   # 1 - patched_accuracy (when attack causes wrong label)
    n_trials:         int
    patch_fraction:   float
    severity:         str        # "critical" | "high" | "moderate" | "low"
    recommendation:   str


class PatchRobustnessTester:
    """
    Tests model robustness against physical adversarial patches.

    Parameters
    ----------
    model_fn   : Callable(input_vector: List[float]) → int (predicted class).
    label_fn   : Callable(index: int) → int (true class for sample index).
    input_fn   : Callable(index: int) → List[float] (clean input for sample index).
    seed       : Random seed for reproducibility.
    """

    def __init__(
        self,
        model_fn:  Callable,
        label_fn:  Callable,
        input_fn:  Callable,
        seed:      int = 42,
    ):
        self._model   = model_fn
        self._label   = label_fn
        self._input   = input_fn
        random.seed(seed)

    def evaluate(self, config: PatchAttackConfig) -> PatchRobustnessResult:
        n_correct_clean   = 0
        n_correct_patched = 0

        for i in range(config.n_trials):
            x     = self._input(i)
            label = self._label(i)

            # Clean prediction
            if self._model(x) == label:
                n_correct_clean += 1

            # Patched prediction
            patched = self._apply_patch(x, config)
            if self._model(patched) == label:
                n_correct_patched += 1

        n = config.n_trials
        clean_acc   = n_correct_clean   / n
        patched_acc = n_correct_patched / n
        drop        = clean_acc - patched_acc
        asr         = 1.0 - patched_acc

        severity = (
            "critical" if drop > 0.30 else
            "high"     if drop > 0.15 else
            "moderate" if drop > 0.05 else
            "low"
        )
        rec = (
            "Apply adversarial training with patch augmentation." if severity in ("critical", "high")
            else "Consider patch detection preprocessing." if severity == "moderate"
            else "Model shows acceptable patch robustness."
        )
        return PatchRobustnessResult(
            clean_accuracy      = round(clean_acc, 4),
            patched_accuracy    = round(patched_acc, 4),
            accuracy_drop       = round(drop, 4),
            attack_success_rate = round(asr, 4),
            n_trials            = n,
            patch_fraction      = config.patch_fraction,
            severity            = severity,
            recommendation      = rec,
        )

    def _apply_patch(self, x: List[float], cfg: PatchAttackConfig) -> List[float]:
        patched  = list(x)
        n_patch  = max(1, int(len(x) * cfg.patch_fraction))
        indices  = random.sample(range(len(x)), n_patch)
        val      = cfg.patch_value
        for idx in indices:
            patched[idx] = val if val is not None else random.uniform(-1.0, 1.0)
        return patched
