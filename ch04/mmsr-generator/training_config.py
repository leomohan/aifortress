"""
training_config.py  —  Training configuration schema and collector
AI Fortress · Chapter 4 · Code Sample 4.C
"""
from __future__ import annotations
import platform, sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class TrainingConfig:
    model_name:       str
    model_version:    str
    task_type:        str              # "classification" | "regression" | "generation" | etc.
    framework:        str              # "pytorch" | "tensorflow" | "jax"
    framework_version: str
    python_version:   str = ""
    architecture:     str = ""        # e.g. "ResNet-50", "BERT-base"
    n_parameters:     Optional[int] = None
    epochs:           Optional[int] = None
    batch_size:       Optional[int] = None
    learning_rate:    Optional[float] = None
    optimizer:        str = ""
    loss_function:    str = ""
    random_seed:      Optional[int] = None
    mixed_precision:  bool = False
    gradient_clipping: Optional[float] = None
    extra_hparams:    Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.python_version:
            self.python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    def security_gaps(self) -> List[str]:
        """Return list of security-relevant fields that are not set."""
        gaps = []
        if self.random_seed is None:
            gaps.append("random_seed: not set — training is non-reproducible")
        if not self.gradient_clipping:
            gaps.append("gradient_clipping: not set — susceptible to exploding gradients")
        return gaps

    def to_dict(self) -> dict:
        return asdict(self)
