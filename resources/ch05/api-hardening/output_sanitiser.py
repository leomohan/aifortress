"""
output_sanitiser.py  —  Response scrubbing and confidence suppression
AI Fortress · Chapter 5 · Code Sample 5.A

Scrubs ML model outputs before returning them to API callers:
  1. Confidence suppression — clips or rounds scores above a threshold
     to defend against membership inference and model extraction
  2. Top-k truncation — returns only the top-k predictions, hiding
     the full probability distribution
  3. PII redaction — scrubs PII patterns from text generation outputs
  4. Output length cap — truncates excessively long outputs
  5. Entropy guard — flags high-entropy outputs that may leak model internals
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class SanitisedOutput:
    original_type: str           # "classification" | "regression" | "text"
    data:          Any
    suppressed:    bool = False  # True if confidence was suppressed
    truncated:     bool = False  # True if output was length-truncated
    pii_redacted:  bool = False
    high_entropy:  bool = False


# PII patterns for text output scrubbing
_PII_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),                   # SSN
    re.compile(r"\b(?:4\d{3}|5[1-5]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),  # card
    re.compile(r"\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b"),  # phone US
]


class OutputSanitiser:
    """
    Scrubs ML API responses before returning to callers.

    Parameters
    ----------
    suppress_confidence_above : Clip probabilities above this value (default 0.95).
                                Prevents exact confidence fishing for membership inference.
    top_k                     : Return only top-k class probabilities (None = all).
    round_decimals            : Round confidence scores to N decimal places.
    max_text_chars            : Truncate text outputs longer than this.
    entropy_alert_threshold   : Flag outputs with Shannon entropy above this value.
    redact_pii                : Apply PII regex scrubbing to text outputs.
    """

    def __init__(
        self,
        suppress_confidence_above: float = 0.95,
        top_k:                     Optional[int] = None,
        round_decimals:            int   = 3,
        max_text_chars:            int   = 4096,
        entropy_alert_threshold:   float = 4.0,
        redact_pii:                bool  = True,
    ):
        self.suppress_confidence_above = suppress_confidence_above
        self.top_k                     = top_k
        self.round_decimals            = round_decimals
        self.max_text_chars            = max_text_chars
        self.entropy_alert_threshold   = entropy_alert_threshold
        self.redact_pii                = redact_pii

    def sanitise_classification(
        self,
        probs:   np.ndarray,
        labels:  Optional[List[str]] = None,
    ) -> SanitisedOutput:
        """Sanitise a probability distribution from a classification model."""
        probs      = np.array(probs, dtype=float)
        suppressed = False

        # ── Confidence suppression ────────────────────────────────────────
        mask = probs > self.suppress_confidence_above
        if mask.any():
            probs[mask] = self.suppress_confidence_above
            # Re-normalise
            total = probs.sum()
            if total > 0:
                probs = probs / total
            suppressed = True

        # ── Top-k truncation ──────────────────────────────────────────────
        if self.top_k and len(probs) > self.top_k:
            top_idx = np.argsort(probs)[::-1][: self.top_k]
            if labels:
                data = {labels[i]: round(float(probs[i]), self.round_decimals)
                        for i in top_idx}
            else:
                data = {int(i): round(float(probs[i]), self.round_decimals)
                        for i in top_idx}
        else:
            probs_rounded = np.round(probs, self.round_decimals)
            if labels:
                data = dict(zip(labels, probs_rounded.tolist()))
            else:
                data = probs_rounded.tolist()

        # ── Entropy check ─────────────────────────────────────────────────
        entropy     = self._shannon_entropy(probs)
        high_ent    = entropy > self.entropy_alert_threshold

        return SanitisedOutput(
            original_type = "classification",
            data          = data,
            suppressed    = suppressed,
            high_entropy  = high_ent,
        )

    def sanitise_text(self, text: str) -> SanitisedOutput:
        """Sanitise a text generation output."""
        pii_redacted = False
        truncated    = False

        if self.redact_pii:
            original = text
            for pat in _PII_PATTERNS:
                text = pat.sub("[REDACTED]", text)
            pii_redacted = text != original

        if len(text) > self.max_text_chars:
            text      = text[: self.max_text_chars] + " [TRUNCATED]"
            truncated = True

        return SanitisedOutput(
            original_type = "text",
            data          = text,
            pii_redacted  = pii_redacted,
            truncated     = truncated,
        )

    def sanitise_regression(self, value: float) -> SanitisedOutput:
        """Sanitise a scalar regression output."""
        return SanitisedOutput(
            original_type = "regression",
            data          = round(float(value), self.round_decimals),
        )

    @staticmethod
    def _shannon_entropy(probs: np.ndarray) -> float:
        p = probs[probs > 0]
        return float(-np.sum(p * np.log2(p)))
