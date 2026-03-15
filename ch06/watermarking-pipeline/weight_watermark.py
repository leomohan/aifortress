"""
weight_watermark.py  —  Weight perturbation watermark embed and verify
AI Fortress · Chapter 6 · Code Sample 6.B

Embeds an owner's secret bit-string into model weights by slightly perturbing
selected parameters. The watermark is:
  - Imperceptible: perturbation magnitude << weight standard deviation
  - Survives moderate fine-tuning and weight pruning
  - Verifiable without model access beyond reading weights
  - Keyed: only the holder of the secret key can locate and extract the mark

Algorithm:
  1. Derive a PRNG seed from the owner secret + model name
  2. Select K weight indices using the seeded PRNG
  3. For each selected weight w_i and watermark bit b_i:
       if b_i = 1: push w_i toward +δ (add δ if w_i < 0, else clip)
       if b_i = 0: push w_i toward -δ
  4. Verification: read sign of selected weights → decoded bits → BER vs watermark

Framework-agnostic: weights represented as a flat numpy array.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np


@dataclass
class WeightWatermarkKey:
    key_id:       str
    owner_id:     str
    model_name:   str
    bit_string:   List[int]    # 0/1 watermark bits
    weight_indices: List[int]  # flat weight indices where bits are encoded
    delta:        float        # perturbation magnitude
    n_weights_total: int       # total flat weight count (for validation)
    created_at:   str

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.__dict__), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "WeightWatermarkKey":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


@dataclass
class WatermarkVerifyResult:
    detected:        bool
    bit_error_rate:  float      # fraction of bits decoded incorrectly
    threshold_ber:   float      # BER above which detection fails
    decoded_bits:    List[int]
    watermark_bits:  List[int]
    p_value:         float      # binomial test p-value


class WeightWatermarker:
    """
    Embeds and verifies a weight-based ownership watermark.

    Parameters
    ----------
    owner_id     : Dataset/model owner identifier
    n_bits       : Number of watermark bits to embed (default 64)
    delta        : Perturbation magnitude as fraction of weight std (default 0.03)
    threshold_ber: Maximum BER to accept as "watermark detected" (default 0.15)
    """

    def __init__(
        self,
        owner_id:      str,
        n_bits:        int   = 64,
        delta:         float = 0.03,
        threshold_ber: float = 0.15,
    ):
        self.owner_id      = owner_id
        self.n_bits        = n_bits
        self.delta         = delta
        self.threshold_ber = threshold_ber

    def embed(
        self,
        weights:    np.ndarray,   # flat 1-D weight array
        model_name: str,
        secret:     bytes,
        bit_string: Optional[List[int]] = None,
    ) -> Tuple[np.ndarray, WeightWatermarkKey]:
        """
        Embed watermark into `weights`. Returns (modified_weights, key).

        Parameters
        ----------
        weights    : Flat 1-D numpy array of model weights
        model_name : Model identifier (used in key derivation)
        secret     : Owner secret bytes
        bit_string : Optional custom bit string; generated randomly if None
        """
        weights    = np.array(weights, dtype=float)
        total      = len(weights)

        # Derive PRNG seed
        seed_bytes = hashlib.sha256(secret + model_name.encode()).digest()[:8]
        seed       = int.from_bytes(seed_bytes, "big")
        rng        = np.random.default_rng(seed)

        # Generate bit string if not provided
        if bit_string is None:
            bit_string = rng.integers(0, 2, self.n_bits).tolist()
        bits = bit_string[: self.n_bits]

        # Select weight indices
        indices = rng.choice(total, self.n_bits, replace=False).tolist()

        # Compute adaptive delta
        w_std  = float(weights.std()) + 1e-12
        delta  = self.delta * w_std

        # Embed
        modified = weights.copy()
        for idx, bit in zip(indices, bits):
            if bit == 1:
                modified[idx] = abs(modified[idx]) + delta
            else:
                modified[idx] = -(abs(modified[idx]) + delta)

        key = WeightWatermarkKey(
            key_id         = str(uuid.uuid4()),
            owner_id       = self.owner_id,
            model_name     = model_name,
            bit_string     = bits,
            weight_indices = indices,
            delta          = delta,
            n_weights_total = total,
            created_at     = datetime.now(timezone.utc).isoformat(),
        )
        return modified, key

    def verify(
        self,
        weights: np.ndarray,
        key:     WeightWatermarkKey,
    ) -> WatermarkVerifyResult:
        """
        Verify whether `weights` contain the watermark described by `key`.
        """
        from scipy import stats as sp_stats

        weights = np.array(weights, dtype=float)
        if len(weights) != key.n_weights_total:
            return WatermarkVerifyResult(
                detected=False, bit_error_rate=1.0,
                threshold_ber=self.threshold_ber,
                decoded_bits=[], watermark_bits=key.bit_string,
                p_value=1.0,
            )

        decoded = []
        for idx in key.weight_indices:
            decoded.append(1 if weights[idx] > 0 else 0)

        errors  = sum(d != w for d, w in zip(decoded, key.bit_string))
        ber     = errors / len(key.bit_string)

        # Binomial test: H₀ = random guessing (p=0.5), H₁ = below threshold
        n_correct = len(key.bit_string) - errors
        p_value   = float(sp_stats.binom_test(
            n_correct, len(key.bit_string), 0.5, alternative="greater"
        ))

        return WatermarkVerifyResult(
            detected        = ber <= self.threshold_ber,
            bit_error_rate  = round(ber, 4),
            threshold_ber   = self.threshold_ber,
            decoded_bits    = decoded,
            watermark_bits  = key.bit_string,
            p_value         = round(p_value, 8),
        )
