"""
feature_squeezer.py  —  Feature squeezing adversarial input detector
AI Fortress · Chapter 5 · Code Sample 5.B

Feature squeezing (Xu et al. 2018) detects adversarial examples by comparing
model predictions on the original input versus a "squeezed" version:

  - Bit-depth reduction  — reduces colour/float precision, collapsing
    small adversarial perturbations that live in fine-grained pixel space
  - Spatial smoothing    — applies a median or Gaussian filter, blurring
    local adversarial patterns that require spatial precision

If the L1 distance between the original and squeezed prediction vectors
exceeds a threshold, the input is flagged as adversarial.

The threshold is calibrated on clean validation data so that the false
positive rate stays below a target level (e.g. 5%).

Framework-agnostic: accepts a score_fn callable (numpy array → score array).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

import numpy as np
from scipy.ndimage import uniform_filter


@dataclass
class SqueezerResult:
    is_adversarial:      bool
    l1_distance:         float         # distance between original and squeezed scores
    threshold:           float
    original_prediction: int
    squeezed_prediction: int
    squeezer_used:       str           # "bit_depth" | "spatial" | "combined"


class FeatureSqueezer:
    """
    Feature squeezing detector for adversarial inputs.

    Parameters
    ----------
    bit_depth          : Target bit depth for reduction (e.g. 4 = 16 levels).
                         Original float inputs assumed in [0, 1].
    spatial_smoothing  : Whether to apply spatial smoothing (median/uniform filter).
    smooth_kernel_size : Kernel size for spatial smoothing filter.
    threshold          : L1 decision threshold. Calibrate with calibrate().
    """

    def __init__(
        self,
        bit_depth:          int   = 4,
        spatial_smoothing:  bool  = True,
        smooth_kernel_size: int   = 3,
        threshold:          float = 0.05,
    ):
        self.bit_depth          = bit_depth
        self.spatial_smoothing  = spatial_smoothing
        self.smooth_kernel_size = smooth_kernel_size
        self.threshold          = threshold

    def detect(
        self,
        original:  np.ndarray,
        score_fn:  Callable[[np.ndarray], np.ndarray],
    ) -> SqueezerResult:
        """
        Detect whether `original` is adversarial by comparing predictions
        on original vs squeezed versions.

        Parameters
        ----------
        original : Input array (float, values in [0, 1] for image inputs).
        score_fn : Callable that maps an input array to a score/prob vector.
        """
        orig_scores = np.asarray(score_fn(original), dtype=float)
        orig_pred   = int(np.argmax(orig_scores))

        # Try bit-depth squeezer
        squeezed_bd    = self._reduce_bit_depth(original)
        scores_bd      = np.asarray(score_fn(squeezed_bd), dtype=float)
        l1_bd          = float(np.sum(np.abs(orig_scores - scores_bd)))

        if self.spatial_smoothing:
            squeezed_sp = self._spatial_smooth(original)
            scores_sp   = np.asarray(score_fn(squeezed_sp), dtype=float)
            l1_sp       = float(np.sum(np.abs(orig_scores - scores_sp)))
            l1_distance = max(l1_bd, l1_sp)
            sq_scores   = scores_sp if l1_sp >= l1_bd else scores_bd
            squeezer    = "combined"
        else:
            l1_distance = l1_bd
            sq_scores   = scores_bd
            squeezer    = "bit_depth"

        sq_pred = int(np.argmax(sq_scores))

        return SqueezerResult(
            is_adversarial      = l1_distance > self.threshold,
            l1_distance         = round(l1_distance, 6),
            threshold           = self.threshold,
            original_prediction = orig_pred,
            squeezed_prediction = sq_pred,
            squeezer_used       = squeezer,
        )

    def calibrate(
        self,
        clean_inputs: List[np.ndarray],
        score_fn:     Callable[[np.ndarray], np.ndarray],
        fpr_target:   float = 0.05,
    ) -> float:
        """
        Calibrate the detection threshold on clean (non-adversarial) inputs
        so that the false positive rate ≤ fpr_target.

        Returns the calibrated threshold and sets self.threshold.
        """
        distances = []
        for x in clean_inputs:
            orig_scores  = np.asarray(score_fn(x), dtype=float)
            squeezed     = self._reduce_bit_depth(x)
            sq_scores    = np.asarray(score_fn(squeezed), dtype=float)
            distances.append(float(np.sum(np.abs(orig_scores - sq_scores))))

            if self.spatial_smoothing:
                squeezed_sp = self._spatial_smooth(x)
                sp_scores   = np.asarray(score_fn(squeezed_sp), dtype=float)
                distances[-1] = max(distances[-1],
                                    float(np.sum(np.abs(orig_scores - sp_scores))))

        # Set threshold at the (1 - fpr_target) quantile of clean distances
        threshold    = float(np.quantile(distances, 1.0 - fpr_target))
        self.threshold = threshold
        return threshold

    # ── Squeezing transforms ──────────────────────────────────────────────────

    def _reduce_bit_depth(self, x: np.ndarray) -> np.ndarray:
        """Reduce to `bit_depth` bits by quantising into 2^bit_depth levels."""
        levels = 2 ** self.bit_depth - 1
        return np.round(x * levels) / levels

    def _spatial_smooth(self, x: np.ndarray) -> np.ndarray:
        """Apply uniform spatial smoothing (approximates median filter)."""
        if x.ndim == 1:
            return uniform_filter(x, size=self.smooth_kernel_size)
        # For 2-D+ arrays apply filter along all axes
        return uniform_filter(x.astype(float),
                              size=self.smooth_kernel_size).astype(x.dtype)
