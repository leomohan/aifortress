"""
gradient_clipper.py  —  Per-sample gradient L2-norm clipping
AI Fortress · Chapter 13 · Code Sample 13.A

Implements the core DP-SGD primitive: clip each per-sample gradient
to L2 norm ≤ C, then average. This bounds the sensitivity of the
gradient to any single training example before Gaussian noise is added.

This module intentionally has no torch dependency so it can be used
in educational contexts and non-PyTorch ML frameworks.
The input is a list of per-sample gradient vectors (lists of floats).

Algorithm (Abadi et al., 2016):
  1. For each sample i:  g̃_i = g_i / max(1, ||g_i||₂ / C)
  2. Average:            ḡ   = (1/B) Σ g̃_i
  3. Caller adds noise:  ḡ + N(0, σ²C²I)
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class ClippingStats:
    n_samples:       int
    n_clipped:       int
    clip_fraction:   float
    mean_norm_before: float
    mean_norm_after:  float
    max_grad_norm:   float    # C


def l2_norm(vector: List[float]) -> float:
    """Compute the L2 norm of a vector."""
    return math.sqrt(sum(x * x for x in vector))


def clip_gradient(
    gradient: List[float],
    max_norm: float,
) -> Tuple[List[float], float]:
    """
    Clip a single gradient vector to L2 norm ≤ max_norm.
    Returns (clipped_gradient, original_norm).
    """
    norm = l2_norm(gradient)
    if norm > max_norm:
        scale = max_norm / norm
        return [x * scale for x in gradient], norm
    return list(gradient), norm


def clip_and_aggregate(
    per_sample_gradients: List[List[float]],
    max_grad_norm:        float,
) -> Tuple[List[float], ClippingStats]:
    """
    Clip per-sample gradients and compute the mean clipped gradient.

    Parameters
    ----------
    per_sample_gradients : List of gradient vectors, one per training sample.
    max_grad_norm        : Clipping threshold C.

    Returns
    -------
    (mean_clipped_gradient, ClippingStats)
    """
    if not per_sample_gradients:
        raise ValueError("per_sample_gradients must not be empty")

    dim      = len(per_sample_gradients[0])
    clipped:  List[List[float]] = []
    norms_before: List[float]   = []
    n_clipped = 0

    for grad in per_sample_gradients:
        if len(grad) != dim:
            raise ValueError(
                f"All gradient vectors must have the same dimension. "
                f"Expected {dim}, got {len(grad)}"
            )
        clipped_grad, orig_norm = clip_gradient(grad, max_grad_norm)
        norms_before.append(orig_norm)
        if orig_norm > max_grad_norm:
            n_clipped += 1
        clipped.append(clipped_grad)

    n = len(clipped)
    mean_grad = [sum(clipped[i][j] for i in range(n)) / n for j in range(dim)]
    norms_after = [l2_norm(g) for g in clipped]

    stats = ClippingStats(
        n_samples        = n,
        n_clipped        = n_clipped,
        clip_fraction    = n_clipped / n,
        mean_norm_before = sum(norms_before) / n,
        mean_norm_after  = sum(norms_after)  / n,
        max_grad_norm    = max_grad_norm,
    )
    return mean_grad, stats


def add_gaussian_noise(
    gradient:         List[float],
    noise_multiplier: float,
    max_grad_norm:    float,
    n_samples:        int,
) -> List[float]:
    """
    Add calibrated Gaussian noise to a mean gradient.

    The noise std dev = noise_multiplier * max_grad_norm / n_samples
    (sensitivity = max_grad_norm / n_samples for the mean).
    """
    import random
    sigma = noise_multiplier * max_grad_norm / n_samples
    return [x + random.gauss(0, sigma) for x in gradient]
