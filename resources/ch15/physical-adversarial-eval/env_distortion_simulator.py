"""
env_distortion_simulator.py  —  Environmental distortion simulator for edge AI
AI Fortress · Chapter 15 · Code Sample 15.E

Simulates real-world environmental distortions that degrade edge
model accuracy:
  - Gaussian noise      : sensor noise, low-light camera artefacts
  - Clipping/saturation : overexposure, blown-out highlights
  - Dropout             : occlusion, packet loss in sensor streams
  - Quantisation noise  : INT8 / INT4 quantisation artefacts
  - Blur                : motion blur, lens defocus

Each distortion is parameterised and applied to an input vector.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class DistortionConfig:
    distortion_type: str    # "gaussian" | "clip" | "dropout" | "quantise" | "blur"
    severity:        float  # 0–1; interpretation varies by type


@dataclass
class DistortionEvalResult:
    distortion_type:  str
    severity:         float
    clean_accuracy:   float
    distorted_accuracy: float
    accuracy_drop:    float
    n_trials:         int


class EnvironmentalDistortionSimulator:
    """
    Evaluates model robustness under environmental distortions.

    Parameters
    ----------
    model_fn : Callable(List[float]) → int.
    label_fn : Callable(int) → int.
    input_fn : Callable(int) → List[float].
    seed     : Random seed.
    """

    def __init__(
        self,
        model_fn: Callable,
        label_fn: Callable,
        input_fn: Callable,
        seed:     int = 0,
    ):
        self._model = model_fn
        self._label = label_fn
        self._input = input_fn
        random.seed(seed)

    def evaluate(
        self,
        configs: List[DistortionConfig],
        n_trials: int = 50,
    ) -> List[DistortionEvalResult]:
        results = []
        for cfg in configs:
            n_clean, n_dist = 0, 0
            for i in range(n_trials):
                x     = self._input(i)
                label = self._label(i)
                if self._model(x) == label:
                    n_clean += 1
                distorted = self._distort(x, cfg)
                if self._model(distorted) == label:
                    n_dist += 1

            clean_acc = n_clean / n_trials
            dist_acc  = n_dist  / n_trials
            results.append(DistortionEvalResult(
                distortion_type    = cfg.distortion_type,
                severity           = cfg.severity,
                clean_accuracy     = round(clean_acc, 4),
                distorted_accuracy = round(dist_acc, 4),
                accuracy_drop      = round(clean_acc - dist_acc, 4),
                n_trials           = n_trials,
            ))
        return results

    def _distort(self, x: List[float], cfg: DistortionConfig) -> List[float]:
        t, s = cfg.distortion_type, cfg.severity
        if t == "gaussian":
            return [v + random.gauss(0, s) for v in x]
        elif t == "clip":
            limit = 1.0 - s
            return [max(-limit, min(limit, v)) for v in x]
        elif t == "dropout":
            return [0.0 if random.random() < s else v for v in x]
        elif t == "quantise":
            levels = max(2, int(256 * (1 - s)))
            return [round(v * levels) / levels for v in x]
        elif t == "blur":
            # Simple moving-average blur
            k = max(1, int(len(x) * s * 0.1))
            blurred = list(x)
            for i in range(len(x)):
                window = x[max(0, i-k): i+k+1]
                blurred[i] = sum(window) / len(window)
            return blurred
        return list(x)
