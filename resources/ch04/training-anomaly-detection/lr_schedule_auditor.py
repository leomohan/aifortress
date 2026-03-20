"""
lr_schedule_auditor.py  —  Learning rate schedule verification
AI Fortress · Chapter 4 · Code Sample 4.B

Verifies that the actual learning rate at each step matches the expected
schedule. Schedule manipulation is a subtle but effective attack: by
inflating the LR during specific steps, an attacker can amplify the
effect of poisoned batches processed at those steps.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

import numpy as np


@dataclass
class LRAnomaly:
    step:        int
    actual_lr:   float
    expected_lr: float
    deviation:   float      # relative deviation: |actual - expected| / expected
    severity:    str
    description: str


class LRScheduleAuditor:
    """
    Verifies actual LR against an expected schedule function.

    Parameters
    ----------
    schedule_fn        : Callable(step: int) → float
                         The expected learning rate at a given step.
                         Can wrap any PyTorch / optax / tf schedule.
    tolerance          : Relative tolerance (default 0.01 = 1%)
    critical_tolerance : Relative deviation for critical alert (default 0.10 = 10%)
    """

    def __init__(
        self,
        schedule_fn:        Callable[[int], float],
        tolerance:          float = 0.01,
        critical_tolerance: float = 0.10,
    ):
        self.schedule_fn        = schedule_fn
        self.tolerance          = tolerance
        self.critical_tolerance = critical_tolerance
        self.anomalies: List[LRAnomaly] = []

    def observe(self, step: int, actual_lr: float) -> Optional[LRAnomaly]:
        expected = self.schedule_fn(step)
        if expected == 0:
            return None
        deviation = abs(actual_lr - expected) / abs(expected)
        if deviation > self.tolerance:
            severity = "critical" if deviation > self.critical_tolerance else "warning"
            anomaly  = LRAnomaly(
                step        = step,
                actual_lr   = actual_lr,
                expected_lr = expected,
                deviation   = round(deviation, 6),
                severity    = severity,
                description = (
                    f"Step {step}: LR deviation {deviation:.1%} "
                    f"(actual={actual_lr:.6e}, expected={expected:.6e}). "
                    "Possible learning rate schedule manipulation."
                ),
            )
            self.anomalies.append(anomaly)
            return anomaly
        return None

    def audit_history(
        self, steps: List[int], actual_lrs: List[float]
    ) -> List[LRAnomaly]:
        """Audit a batch of historical (step, lr) observations."""
        return [a for s, lr in zip(steps, actual_lrs)
                if (a := self.observe(s, lr)) is not None]


# ── Common schedule helpers ───────────────────────────────────────────────────

def cosine_decay_schedule(
    initial_lr: float,
    total_steps: int,
    min_lr: float = 0.0,
) -> Callable[[int], float]:
    import math
    def fn(step: int) -> float:
        t = min(step, total_steps) / total_steps
        return min_lr + 0.5 * (initial_lr - min_lr) * (1 + math.cos(math.pi * t))
    return fn


def warmup_then_decay_schedule(
    peak_lr:      float,
    warmup_steps: int,
    total_steps:  int,
    min_lr:       float = 0.0,
) -> Callable[[int], float]:
    cosine = cosine_decay_schedule(peak_lr, total_steps - warmup_steps, min_lr)
    def fn(step: int) -> float:
        if step < warmup_steps:
            return peak_lr * step / max(warmup_steps, 1)
        return cosine(step - warmup_steps)
    return fn
