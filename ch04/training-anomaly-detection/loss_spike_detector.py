"""
loss_spike_detector.py  —  Step/epoch loss anomaly detection
AI Fortress · Chapter 4 · Code Sample 4.B

Monitors training loss values in real time.  Two complementary detectors:

  1. Z-score detector — maintains a rolling window of recent losses and flags
     any observation whose Z-score exceeds a threshold. Sensitive to sharp spikes.

  2. IQR detector — flags observations outside Q1 - k*IQR or Q3 + k*IQR.
     More robust to skewed distributions than Z-score.

Sudden, unexplained loss spikes indicate:
  - A poisoned batch reached the model
  - An adversarial gradient update was injected
  - A corrupted data sample with extreme feature values
  - Hardware fault (NaN/Inf propagation from bit-flip)
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Deque, List, Optional

import numpy as np


@dataclass
class LossAnomaly:
    step:        int
    loss:        float
    method:      str        # "z_score" | "iqr" | "nan_inf"
    severity:    str        # "warning" | "critical"
    description: str
    window_mean: Optional[float] = None
    window_std:  Optional[float] = None
    z_score:     Optional[float] = None


class LossSpikeDetector:
    """
    Real-time rolling-window loss anomaly detector.

    Parameters
    ----------
    window        : Number of recent steps to use as the reference window
    z_threshold   : Z-score above which a loss value is flagged (default 3.5)
    iqr_k         : IQR multiplier for outlier detection (default 3.0)
    min_window    : Minimum observations before detection activates
    """

    def __init__(
        self,
        window:      int   = 50,
        z_threshold: float = 3.5,
        iqr_k:       float = 3.0,
        min_window:  int   = 10,
    ):
        self.window      = window
        self.z_threshold = z_threshold
        self.iqr_k       = iqr_k
        self.min_window  = min_window
        self._history:   Deque[float] = deque(maxlen=window)
        self.anomalies:  List[LossAnomaly] = []

    def observe(self, step: int, loss: float) -> Optional[LossAnomaly]:
        """
        Record a loss observation. Returns a LossAnomaly if one is detected,
        else None. Thread-safe for single-producer use.
        """
        # ── NaN / Inf check ───────────────────────────────────────────────
        if not np.isfinite(loss):
            anomaly = LossAnomaly(
                step        = step,
                loss        = float(loss),
                method      = "nan_inf",
                severity    = "critical",
                description = (
                    f"Step {step}: loss is {'NaN' if np.isnan(loss) else 'Inf'}. "
                    "Likely cause: exploding gradients, poisoned batch, or hardware fault. "
                    "Training should be halted."
                ),
            )
            self.anomalies.append(anomaly)
            return anomaly

        finding: Optional[LossAnomaly] = None

        if len(self._history) >= self.min_window:
            arr  = np.array(self._history)
            mean = float(arr.mean())
            std  = float(arr.std())

            # ── Z-score test ──────────────────────────────────────────────
            if std > 0:
                z = (loss - mean) / std
                if abs(z) > self.z_threshold:
                    severity = "critical" if abs(z) > self.z_threshold * 1.5 else "warning"
                    finding  = LossAnomaly(
                        step        = step,
                        loss        = round(loss, 6),
                        method      = "z_score",
                        severity    = severity,
                        description = (
                            f"Step {step}: loss spike detected (loss={loss:.4f}, "
                            f"Z={z:.2f}, window μ={mean:.4f}, σ={std:.4f}). "
                            "Possible poisoned batch or adversarial gradient injection."
                        ),
                        window_mean = round(mean, 6),
                        window_std  = round(std, 6),
                        z_score     = round(z, 4),
                    )

            # ── IQR test (only if Z-score didn't already flag) ────────────
            if finding is None:
                q1, q3 = float(np.percentile(arr, 25)), float(np.percentile(arr, 75))
                iqr    = q3 - q1
                if iqr > 0:
                    upper = q3 + self.iqr_k * iqr
                    lower = q1 - self.iqr_k * iqr
                    if loss > upper or loss < lower:
                        finding = LossAnomaly(
                            step        = step,
                            loss        = round(loss, 6),
                            method      = "iqr",
                            severity    = "warning",
                            description = (
                                f"Step {step}: loss {loss:.4f} outside IQR bounds "
                                f"[{lower:.4f}, {upper:.4f}] (k={self.iqr_k})."
                            ),
                        )

        self._history.append(loss)
        if finding:
            self.anomalies.append(finding)
        return finding

    def observe_epoch(self, epoch: int, epoch_loss: float) -> Optional[LossAnomaly]:
        """Convenience wrapper — observe a per-epoch aggregate loss."""
        # Use step=epoch * 1000 to avoid index collision with per-step history
        return self.observe(step=epoch * 1000, loss=epoch_loss)

    def summary(self) -> dict:
        return {
            "total_anomalies": len(self.anomalies),
            "critical": sum(1 for a in self.anomalies if a.severity == "critical"),
            "warnings":  sum(1 for a in self.anomalies if a.severity == "warning"),
            "nan_inf":   sum(1 for a in self.anomalies if a.method == "nan_inf"),
        }
