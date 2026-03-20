"""
confidence_suppressor.py  —  Prediction confidence capping and binning
AI Fortress · Chapter 13 · Code Sample 13.E

Reduces information leakage through model confidence scores by:
  1. Capping maximum confidence (e.g. to 0.95 to prevent over-confident outputs)
  2. Quantising confidence to discrete bins (reduces precision)

Suppression levels:
  coarse — 5 bins  (0.2 precision)
  medium — 10 bins (0.1 precision)
  fine   — 20 bins (0.05 precision)
  none   — cap only, no binning
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal, Optional


@dataclass
class SuppressedPrediction:
    original_confidence:   float
    suppressed_confidence: float
    predicted_class:       int
    was_capped:            bool
    was_quantised:         bool
    suppression_level:     str


class ConfidenceSuppressor:
    """
    Caps and quantises model prediction confidence.

    Parameters
    ----------
    max_confidence     : Maximum allowed confidence value (default 0.95).
    suppression_level  : "coarse" | "medium" | "fine" | "none".
    """

    _BINS = {"coarse": 5, "medium": 10, "fine": 20, "none": 0}

    def __init__(
        self,
        max_confidence:    float = 0.95,
        suppression_level: Literal["coarse", "medium", "fine", "none"] = "medium",
    ):
        if not (0 < max_confidence <= 1.0):
            raise ValueError("max_confidence must be in (0, 1]")
        if suppression_level not in self._BINS:
            raise ValueError(f"suppression_level must be one of {list(self._BINS)}")
        self._max   = max_confidence
        self._level = suppression_level
        self._n_bins = self._BINS[suppression_level]

    def suppress(
        self,
        confidence:      float,
        predicted_class: int,
    ) -> SuppressedPrediction:
        """Suppress a single confidence value."""
        was_capped = confidence > self._max
        capped     = min(confidence, self._max)

        was_quantised = False
        quantised     = capped
        if self._n_bins > 0:
            bin_width = 1.0 / self._n_bins
            quantised = round(capped / bin_width) * bin_width
            quantised = min(quantised, self._max)
            was_quantised = (quantised != capped)

        return SuppressedPrediction(
            original_confidence   = confidence,
            suppressed_confidence = round(quantised, 6),
            predicted_class       = predicted_class,
            was_capped            = was_capped,
            was_quantised         = was_quantised,
            suppression_level     = self._level,
        )

    def suppress_batch(
        self,
        confidences:      List[float],
        predicted_classes: List[int],
    ) -> List[SuppressedPrediction]:
        if len(confidences) != len(predicted_classes):
            raise ValueError("confidences and predicted_classes must have same length")
        return [
            self.suppress(c, cls)
            for c, cls in zip(confidences, predicted_classes)
        ]

    def information_loss_pct(self) -> float:
        """Estimate % of confidence information lost via quantisation."""
        if self._n_bins == 0:
            return 0.0
        return round((1.0 / self._n_bins) / 1.0 * 100, 1)
