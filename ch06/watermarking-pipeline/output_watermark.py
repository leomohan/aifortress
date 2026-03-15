"""
output_watermark.py  —  Inference-time output watermarking
AI Fortress · Chapter 6 · Code Sample 6.B

Embeds a statistical ownership signal into model outputs at inference time
using a keyed pseudo-random process. The watermark is:
  - Imperceptible in individual outputs
  - Detectable via statistical hypothesis test over a sample of outputs
  - Tied to the owner's secret — cannot be verified without the key

Two modes:
  1. Classification watermark — slightly biases the argmax toward a keyed
     "phantom class" for a fraction of inputs. Verification: binomial test
     on phantom class rate compared to expected base rate.

  2. Soft score perturbation — adds a tiny keyed perturbation to the output
     logits before softmax. Detectable by measuring the mean perturbation
     direction correlation over many outputs.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple

import numpy as np
from scipy import stats


@dataclass
class OutputWatermarkKey:
    key_id:         str
    owner_id:       str
    mode:           str        # "classification" | "soft_perturbation"
    phantom_class:  int        # for classification mode
    bias_rate:      float      # fraction of outputs to bias
    perturbation_direction: List[float]   # for soft mode
    created_at:     str

    def save(self, path: str) -> None:
        import json
        open(path, "w").write(json.dumps(self.__dict__))

    @classmethod
    def load(cls, path: str) -> "OutputWatermarkKey":
        return cls(**json.loads(open(path).read()))


@dataclass
class OutputVerifyResult:
    detected:    bool
    p_value:     float
    test_stat:   float
    n_samples:   int
    mode:        str


class OutputWatermarker:
    """
    Wraps an inference function to embed a keyed watermark in outputs.

    Parameters
    ----------
    owner_id     : Owner identifier
    secret       : Secret bytes for PRNG seeding
    n_classes    : Number of output classes
    mode         : "classification" | "soft_perturbation"
    bias_rate    : Fraction of outputs to bias (classification mode, default 0.05)
    alpha        : Significance level for verification test (default 0.01)
    """

    def __init__(
        self,
        owner_id:    str,
        secret:      bytes,
        n_classes:   int,
        mode:        str   = "soft_perturbation",
        bias_rate:   float = 0.05,
        alpha:       float = 0.01,
    ):
        self.owner_id  = owner_id
        self.mode      = mode
        self.bias_rate = bias_rate
        self.alpha     = alpha

        # Derive watermark parameters from secret
        seed_bytes = hashlib.sha256(secret).digest()[:8]
        seed       = int.from_bytes(seed_bytes, "big")
        rng        = np.random.default_rng(seed)

        self._phantom_class = int(rng.integers(0, n_classes))
        self._direction     = rng.normal(0, 1, n_classes).astype(float)
        self._direction    /= np.linalg.norm(self._direction) + 1e-12
        self._rng           = rng
        self._n_classes     = n_classes

        self._key = OutputWatermarkKey(
            key_id       = str(uuid.uuid4()),
            owner_id     = owner_id,
            mode         = mode,
            phantom_class = self._phantom_class,
            bias_rate    = bias_rate,
            perturbation_direction = self._direction.tolist(),
            created_at   = datetime.now(timezone.utc).isoformat(),
        )

    @property
    def key(self) -> OutputWatermarkKey:
        return self._key

    def watermark_output(self, logits: np.ndarray) -> np.ndarray:
        """
        Apply watermark perturbation to a single output logit vector.
        Call this in your inference pipeline before softmax/argmax.
        """
        logits = np.array(logits, dtype=float)
        if self.mode == "soft_perturbation":
            # Tiny perturbation in the keyed direction
            magnitude  = float(np.std(logits)) * 0.05
            perturbed  = logits + magnitude * self._direction[:len(logits)]
            return perturbed
        elif self.mode == "classification":
            # With probability bias_rate, boost the phantom class
            if self._rng.random() < self.bias_rate:
                logits = logits.copy()
                if self._phantom_class < len(logits):
                    logits[self._phantom_class] += float(np.std(logits)) * 0.5
            return logits
        return logits

    def wrap(self, score_fn: Callable[[np.ndarray], np.ndarray]) -> Callable:
        """Return a wrapped score_fn that embeds the watermark in every output."""
        def watermarked_fn(x: np.ndarray) -> np.ndarray:
            logits = score_fn(x)
            return self.watermark_output(np.asarray(logits))
        return watermarked_fn

    def verify(
        self,
        outputs:   List[np.ndarray],   # list of raw logit/score vectors
        key:       OutputWatermarkKey,
    ) -> OutputVerifyResult:
        """
        Statistical test for watermark presence in a list of outputs.
        """
        direction = np.array(key.perturbation_direction)
        n         = len(outputs)

        if key.mode == "soft_perturbation":
            # Measure mean projection onto watermark direction
            projections = []
            for out in outputs:
                out_arr = np.asarray(out, dtype=float)
                d       = direction[:len(out_arr)]
                d_norm  = d / (np.linalg.norm(d) + 1e-12)
                projections.append(float(np.dot(out_arr, d_norm)))
            t_stat, p_value = stats.ttest_1samp(projections, popmean=0.0, alternative="greater")
            return OutputVerifyResult(
                detected  = bool(p_value < self.alpha),
                p_value   = round(float(p_value), 8),
                test_stat = round(float(t_stat), 6),
                n_samples = n,
                mode      = key.mode,
            )
        elif key.mode == "classification":
            # Binomial test: observed phantom class rate vs expected base rate
            phantom    = key.phantom_class
            phantom_ct = sum(1 for out in outputs if int(np.argmax(out)) == phantom)
            base_rate  = 1.0 / self._n_classes
            result     = stats.binomtest(phantom_ct, n, base_rate, alternative="greater")
            p_value    = float(result.pvalue)
            return OutputVerifyResult(
                detected  = bool(p_value < self.alpha),
                p_value   = round(p_value, 8),
                test_stat = round(float(phantom_ct / n), 6),
                n_samples = n,
                mode      = key.mode,
            )
        return OutputVerifyResult(False, 1.0, 0.0, n, key.mode)
