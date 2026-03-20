"""
attack_simulator.py  —  Framework-agnostic FGSM and PGD attack simulation
AI Fortress · Chapter 5 · Code Sample 5.B

Implements two canonical gradient-based adversarial attacks for red-teaming:

  FGSM (Fast Gradient Sign Method, Goodfellow et al. 2014):
    x_adv = x + ε · sign(∇_x L(f(x), y))
    Single-step attack. Fast but weak — useful as a lower bound.

  PGD (Projected Gradient Descent, Madry et al. 2017):
    x_adv_{t+1} = Π_{B(x,ε)}[ x_adv_t + α · sign(∇_x L(f(x_adv_t), y)) ]
    Iterative attack with projection back to ε-ball. Strong empirical baseline.

Framework-agnostic: both attacks accept a score_fn (numpy → numpy scores)
and approximate gradients numerically via finite differences. This makes them
usable without access to model internals — only API-level access needed.

Use these to test whether your defence pipeline (input smoothing, feature
squeezing) correctly detects the resulting adversarial examples.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import numpy as np


@dataclass
class AttackResult:
    original:       np.ndarray
    adversarial:    np.ndarray
    perturbation:   np.ndarray
    l2_norm:        float
    linf_norm:      float
    original_class: int
    adversarial_class: int
    attack_method:  str
    success:        bool    # True if adversarial_class != original_class


class AdversarialAttackSimulator:
    """
    Simulates FGSM and PGD adversarial attacks using numerical gradient estimation.

    Parameters
    ----------
    epsilon   : Maximum ℓ∞ perturbation budget (e.g. 8/255 ≈ 0.031 for images).
    fd_delta  : Finite-difference step size for gradient approximation.
    clip_min  : Minimum allowed value in perturbed input.
    clip_max  : Maximum allowed value in perturbed input.
    """

    def __init__(
        self,
        epsilon:  float = 8 / 255,
        fd_delta: float = 1e-4,
        clip_min: float = 0.0,
        clip_max: float = 1.0,
    ):
        self.epsilon  = epsilon
        self.fd_delta = fd_delta
        self.clip_min = clip_min
        self.clip_max = clip_max

    def fgsm(
        self,
        x:        np.ndarray,
        score_fn: Callable[[np.ndarray], np.ndarray],
        target_class: Optional[int] = None,
    ) -> AttackResult:
        """
        Fast Gradient Sign Method (untargeted by default).

        For untargeted: maximise loss of the true class.
        For targeted:   minimise loss of target_class (set target_class to desired label).
        """
        x      = np.array(x, dtype=float)
        grad   = self._numerical_gradient(x, score_fn, target_class)
        sign_g = np.sign(grad)

        if target_class is None:
            x_adv = x + self.epsilon * sign_g     # push away from current prediction
        else:
            x_adv = x - self.epsilon * sign_g     # pull toward target class

        x_adv = np.clip(x_adv, self.clip_min, self.clip_max)
        return self._build_result(x, x_adv, score_fn, "FGSM")

    def pgd(
        self,
        x:          np.ndarray,
        score_fn:   Callable[[np.ndarray], np.ndarray],
        n_steps:    int   = 20,
        step_size:  float = 0.003,
        target_class: Optional[int] = None,
        random_start: bool = True,
    ) -> AttackResult:
        """
        Projected Gradient Descent (untargeted by default).

        Parameters
        ----------
        n_steps      : Number of PGD iterations (default 20).
        step_size    : Per-step ℓ∞ step size α (default 0.003 ≈ ε/10 for ε=8/255).
        random_start : Initialise from a random point in the ε-ball (Madry et al.).
        """
        x     = np.array(x, dtype=float)
        x_adv = x.copy()

        if random_start:
            x_adv = x + np.random.uniform(-self.epsilon, self.epsilon, x.shape)
            x_adv = np.clip(x_adv, self.clip_min, self.clip_max)

        for _ in range(n_steps):
            grad   = self._numerical_gradient(x_adv, score_fn, target_class)
            sign_g = np.sign(grad)

            if target_class is None:
                x_adv = x_adv + step_size * sign_g
            else:
                x_adv = x_adv - step_size * sign_g

            # Project back onto ε-ball around original x
            x_adv = np.clip(x_adv, x - self.epsilon, x + self.epsilon)
            x_adv = np.clip(x_adv, self.clip_min, self.clip_max)

        return self._build_result(x, x_adv, score_fn, "PGD")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _numerical_gradient(
        self,
        x:        np.ndarray,
        score_fn: Callable[[np.ndarray], np.ndarray],
        target_class: Optional[int],
    ) -> np.ndarray:
        """
        Estimate ∇_x L via central finite differences.
        L = -log(p[true_class]) for untargeted, -log(p[target]) for targeted.
        """
        scores      = np.asarray(score_fn(x), dtype=float)
        true_class  = int(np.argmax(scores))
        idx         = target_class if target_class is not None else true_class

        grad = np.zeros_like(x, dtype=float)
        it   = np.nditer(x, flags=["multi_index"])

        while not it.finished:
            idx_flat = it.multi_index
            orig_val = x[idx_flat]

            x[idx_flat] = orig_val + self.fd_delta
            s_plus = np.asarray(score_fn(x), dtype=float)
            # Protect against empty / zero score arrays
            p_plus = s_plus[idx] if len(s_plus) > idx else 0.0

            x[idx_flat] = orig_val - self.fd_delta
            s_minus = np.asarray(score_fn(x), dtype=float)
            p_minus = s_minus[idx] if len(s_minus) > idx else 0.0

            x[idx_flat] = orig_val
            # Gradient of -log(p) ≈ -(p_plus - p_minus) / (2*delta*p)
            denom = max(abs((p_plus + p_minus) / 2), 1e-12)
            grad[idx_flat] = -(p_plus - p_minus) / (2 * self.fd_delta * denom)
            it.iternext()

        return grad

    def _build_result(
        self,
        x:        np.ndarray,
        x_adv:    np.ndarray,
        score_fn: Callable[[np.ndarray], np.ndarray],
        method:   str,
    ) -> AttackResult:
        orig_scores  = np.asarray(score_fn(x),     dtype=float)
        adv_scores   = np.asarray(score_fn(x_adv), dtype=float)
        orig_cls     = int(np.argmax(orig_scores))
        adv_cls      = int(np.argmax(adv_scores))
        pert         = x_adv - x

        return AttackResult(
            original          = x,
            adversarial       = x_adv,
            perturbation      = pert,
            l2_norm           = float(np.linalg.norm(pert)),
            linf_norm         = float(np.max(np.abs(pert))),
            original_class    = orig_cls,
            adversarial_class = adv_cls,
            attack_method     = method,
            success           = adv_cls != orig_cls,
        )
