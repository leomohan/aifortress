"""
roles.py  —  ML pipeline role definitions and YAML loader
AI Fortress · Chapter 1 · Code Sample 1.B
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Dict, FrozenSet
import yaml


class Classification(IntEnum):
    PUBLIC       = 0
    INTERNAL     = 1
    CONFIDENTIAL = 2
    RESTRICTED   = 3


@dataclass(frozen=True)
class Role:
    name:                      str
    description:               str
    allowed_actions:           FrozenSet[str]
    allowed_resource_prefixes: FrozenSet[str]
    classification_ceiling:    Classification

    def can_act(self, action: str) -> bool:
        return "*" in self.allowed_actions or action in self.allowed_actions

    def can_access_prefix(self, resource: str) -> bool:
        return any(
            p == "*" or resource.startswith(p)
            for p in self.allowed_resource_prefixes
        )

    def can_access_classification(self, level: Classification) -> bool:
        return level <= self.classification_ceiling


BUILTIN_ROLES: Dict[str, Role] = {
    "data-engineer": Role(
        name="data-engineer",
        description="Ingests and transforms training data. No access to model artifacts.",
        allowed_actions=frozenset({"read", "write", "list"}),
        allowed_resource_prefixes=frozenset({
            "s3://*/raw/", "s3://*/processed/", "s3://*/staging/",
        }),
        classification_ceiling=Classification.CONFIDENTIAL,
    ),
    "ml-engineer": Role(
        name="ml-engineer",
        description="Trains and evaluates models. Read datasets; write model artifacts.",
        allowed_actions=frozenset({"read", "write", "list"}),
        allowed_resource_prefixes=frozenset({
            "s3://*/datasets/", "s3://*/models/", "s3://*/experiments/",
        }),
        classification_ceiling=Classification.CONFIDENTIAL,
    ),
    "ml-researcher": Role(
        name="ml-researcher",
        description="Read-only access to non-PII datasets and published models.",
        allowed_actions=frozenset({"read", "list"}),
        allowed_resource_prefixes=frozenset({
            "s3://*/datasets/non-pii/", "s3://*/models/published/",
        }),
        classification_ceiling=Classification.INTERNAL,
    ),
    "model-validator": Role(
        name="model-validator",
        description="Read-only access to model artifacts and evaluation datasets.",
        allowed_actions=frozenset({"read", "list"}),
        allowed_resource_prefixes=frozenset({
            "s3://*/models/", "s3://*/eval/",
        }),
        classification_ceiling=Classification.CONFIDENTIAL,
    ),
    "auditor": Role(
        name="auditor",
        description="Read-only access to audit logs and metadata. No raw data or weights.",
        allowed_actions=frozenset({"read", "list"}),
        allowed_resource_prefixes=frozenset({
            "s3://*/audit-logs/", "s3://*/metadata/", "s3://*/manifests/",
        }),
        classification_ceiling=Classification.RESTRICTED,
    ),
    "admin": Role(
        name="admin",
        description="Full access. Break-glass only — requires PAM session recording.",
        allowed_actions=frozenset({"*"}),
        allowed_resource_prefixes=frozenset({"*"}),
        classification_ceiling=Classification.RESTRICTED,
    ),
}


def load_roles(config_path: str | Path = "") -> Dict[str, Role]:
    """Load roles from YAML, falling back to BUILTIN_ROLES."""
    if not config_path or not Path(config_path).exists():
        return BUILTIN_ROLES
    with open(config_path) as f:
        raw = yaml.safe_load(f)
    return {
        name: Role(
            name=name,
            description=cfg.get("description", ""),
            allowed_actions=frozenset(cfg.get("allowed_actions", [])),
            allowed_resource_prefixes=frozenset(cfg.get("allowed_resource_prefixes", [])),
            classification_ceiling=Classification[cfg.get("classification_ceiling", "CONFIDENTIAL")],
        )
        for name, cfg in raw.get("roles", {}).items()
    }
