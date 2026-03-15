"""
privacy_engine_wrapper.py  —  DP-SGD privacy engine wrapper
AI Fortress · Chapter 13 · Code Sample 13.A

Wraps the Opacus PrivacyEngine to attach differential privacy to a
PyTorch model training loop. Provides a clean lifecycle and records
privacy spending per training step.

When Opacus / torch are not installed the module degrades gracefully:
the wrapper still works as a configuration and accounting object; only
the actual attach() call to a real model will fail at import time.

Key parameters:
  noise_multiplier (σ) — ratio of Gaussian noise std dev to clip bound.
                          Higher = more privacy, less utility.
  max_grad_norm    (C) — L2 clip bound for per-sample gradients.
  sample_rate          — batch_size / dataset_size. Determines amplification.
  target_epsilon (ε)   — maximum privacy budget to spend.
  target_delta   (δ)   — failure probability (typically 1/N for N records).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class DPConfig:
    noise_multiplier: float
    max_grad_norm:    float
    sample_rate:      float
    target_epsilon:   float
    target_delta:     float
    max_grad_norm_type: str = "flat"   # "flat" | "per-layer"
    secure_rng:       bool = False

    def validate(self) -> None:
        if not (0 < self.sample_rate <= 1):
            raise ValueError(f"sample_rate must be in (0, 1], got {self.sample_rate}")
        if self.noise_multiplier <= 0:
            raise ValueError(f"noise_multiplier must be > 0, got {self.noise_multiplier}")
        if self.max_grad_norm <= 0:
            raise ValueError(f"max_grad_norm must be > 0, got {self.max_grad_norm}")
        if self.target_epsilon <= 0:
            raise ValueError(f"target_epsilon must be > 0, got {self.target_epsilon}")
        if not (0 < self.target_delta < 1):
            raise ValueError(f"target_delta must be in (0, 1), got {self.target_delta}")


@dataclass
class DPTrainingState:
    steps_taken:      int = 0
    epochs_completed: int = 0
    epsilon_spent:    float = 0.0
    best_epsilon:     float = float("inf")
    attached:         bool = False
    attached_at:      str = ""
    detached_at:      str = ""


class PrivacyEngineWrapper:
    """
    Wraps Opacus PrivacyEngine for DP-SGD training.

    Usage (with real PyTorch + Opacus):
        config  = DPConfig(noise_multiplier=1.1, max_grad_norm=1.0,
                           sample_rate=0.01, target_epsilon=8.0, target_delta=1e-5)
        wrapper = PrivacyEngineWrapper(config, audit_path="dp_log.jsonl")
        model, optimiser, data_loader = wrapper.attach(model, optimiser, data_loader)
        # ... training loop ...
        epsilon = wrapper.step_accountant()   # call after each batch
        wrapper.detach()

    Parameters
    ----------
    config     : DPConfig with all privacy hyperparameters.
    audit_path : Optional JSON Lines path for privacy spending events.
    """

    def __init__(
        self,
        config:     DPConfig,
        audit_path: Optional[str | Path] = None,
    ):
        config.validate()
        self.config = config
        self.state  = DPTrainingState()
        self._engine: Any = None
        self._audit = Path(audit_path) if audit_path else None

    def attach(self, model, optimiser, data_loader):
        """
        Attach the Opacus PrivacyEngine to model, optimiser, and data_loader.
        Returns the (possibly wrapped) model, optimiser, data_loader.
        Requires opacus to be installed.
        """
        try:
            from opacus import PrivacyEngine
        except ImportError as exc:
            raise ImportError(
                "opacus is required for attach(). "
                "Install with: pip install opacus"
            ) from exc

        engine = PrivacyEngine(secure_mode=self.config.secure_rng)
        model, optimiser, data_loader = engine.make_private_with_epsilon(
            module        = model,
            optimizer     = optimiser,
            data_loader   = data_loader,
            epochs        = 1,
            target_epsilon= self.config.target_epsilon,
            target_delta  = self.config.target_delta,
            max_grad_norm = self.config.max_grad_norm,
        )
        self._engine              = engine
        self.state.attached       = True
        self.state.attached_at    = datetime.now(timezone.utc).isoformat()
        self._log("engine_attached", noise_multiplier=self.config.noise_multiplier,
                  max_grad_norm=self.config.max_grad_norm,
                  target_epsilon=self.config.target_epsilon)
        return model, optimiser, data_loader

    def step_accountant(self) -> float:
        """
        Compute epsilon spent so far and update state.
        Call once per batch after optimiser.step().
        Returns current epsilon.
        """
        if self._engine is None:
            # Standalone accounting (no real engine) via privacy_accountant module
            from privacy_accountant import RDPAccountant
            accountant = RDPAccountant(
                noise_multiplier=self.config.noise_multiplier,
                sample_rate=self.config.sample_rate,
                delta=self.config.target_delta,
            )
            accountant.compose(self.state.steps_taken + 1)
            epsilon = accountant.get_epsilon()
        else:
            epsilon = self._engine.get_epsilon(delta=self.config.target_delta)

        self.state.steps_taken   += 1
        self.state.epsilon_spent  = epsilon
        self.state.best_epsilon   = min(self.state.best_epsilon, epsilon)

        if epsilon > self.config.target_epsilon:
            self._log("budget_exceeded", epsilon_spent=epsilon,
                      target_epsilon=self.config.target_epsilon)
        return epsilon

    def end_epoch(self) -> None:
        self.state.epochs_completed += 1
        self._log("epoch_completed", epoch=self.state.epochs_completed,
                  epsilon_spent=self.state.epsilon_spent,
                  steps=self.state.steps_taken)

    def detach(self) -> None:
        self.state.attached    = False
        self.state.detached_at = datetime.now(timezone.utc).isoformat()
        self._log("engine_detached", final_epsilon=self.state.epsilon_spent,
                  epochs=self.state.epochs_completed)

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
