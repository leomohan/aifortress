"""
gradient_norm_monitor.py  —  Gradient norm surveillance
AI Fortress · Chapter 4 · Code Sample 4.B

Tracks L2 gradient norms per parameter group across training steps.
Detects:
  - Exploding gradients (norm >> historical mean): adversarial weight injection
  - Vanishing gradients (norm ≈ 0): backdoor masking activity, dead neurons
  - Sudden norm spikes affecting only specific parameter groups: targeted attack

Works without torch: accepts gradient norms as plain floats, so it can
be used with any framework by computing norms externally.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

import numpy as np


@dataclass
class GradientAnomaly:
    step:          int
    group_name:    str
    norm:          float
    severity:      str
    description:   str
    window_mean:   Optional[float] = None
    ratio_to_mean: Optional[float] = None


class GradientNormMonitor:
    """
    Monitors per-group gradient L2 norms for anomalies.

    Parameters
    ----------
    window           : Rolling window size
    explode_ratio    : Ratio (norm / window_mean) above which explosion is flagged
    vanish_threshold : Absolute norm below which vanishing is flagged
    min_window       : Minimum observations before detection activates
    """

    def __init__(
        self,
        window:           int   = 50,
        explode_ratio:    float = 10.0,
        vanish_threshold: float = 1e-7,
        min_window:       int   = 10,
    ):
        self.window           = window
        self.explode_ratio    = explode_ratio
        self.vanish_threshold = vanish_threshold
        self.min_window       = min_window
        self._histories: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=window))
        self.anomalies:  List[GradientAnomaly]   = []

    def observe(
        self,
        step:       int,
        norms:      Dict[str, float],  # group_name → L2 norm
    ) -> List[GradientAnomaly]:
        """
        Record gradient norms for one training step.
        Returns list of anomalies found (may be empty).
        """
        found: List[GradientAnomaly] = []

        for group, norm in norms.items():
            if not np.isfinite(norm):
                a = GradientAnomaly(
                    step=step, group_name=group, norm=norm,
                    severity="critical",
                    description=(
                        f"Step {step}, group '{group}': gradient norm is "
                        f"{'NaN' if np.isnan(norm) else 'Inf'}. "
                        "Training integrity compromised."
                    ),
                )
                found.append(a)
                self.anomalies.append(a)
                self._histories[group].append(0.0)  # placeholder
                continue

            hist = self._histories[group]

            if len(hist) >= self.min_window:
                arr  = np.array(hist)
                mean = float(arr.mean())

                # Explosion
                if mean > 0 and norm / mean > self.explode_ratio:
                    severity = "critical" if norm / mean > self.explode_ratio * 2 else "warning"
                    a = GradientAnomaly(
                        step          = step,
                        group_name    = group,
                        norm          = round(norm, 6),
                        severity      = severity,
                        window_mean   = round(mean, 6),
                        ratio_to_mean = round(norm / mean, 2),
                        description   = (
                            f"Step {step}, group '{group}': gradient EXPLODING "
                            f"(norm={norm:.4e}, {norm/mean:.1f}× window mean {mean:.4e}). "
                            "Possible adversarial weight injection or corrupted batch."
                        ),
                    )
                    found.append(a)
                    self.anomalies.append(a)

                # Vanishing
                elif norm < self.vanish_threshold and mean > self.vanish_threshold * 10:
                    a = GradientAnomaly(
                        step        = step,
                        group_name  = group,
                        norm        = round(norm, 10),
                        severity    = "warning",
                        window_mean = round(mean, 6),
                        description = (
                            f"Step {step}, group '{group}': gradient VANISHING "
                            f"(norm={norm:.2e}, window mean={mean:.4e}). "
                            "Possible backdoor masking or dead neuron activity."
                        ),
                    )
                    found.append(a)
                    self.anomalies.append(a)

            hist.append(norm)

        return found

    def summary(self) -> dict:
        return {
            "total_anomalies": len(self.anomalies),
            "critical": sum(1 for a in self.anomalies if a.severity == "critical"),
            "warnings":  sum(1 for a in self.anomalies if a.severity == "warning"),
            "groups_monitored": list(self._histories.keys()),
        }
