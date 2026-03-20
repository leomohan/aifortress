"""
metadata_extractor.py  —  Model metadata collection and validation
AI Fortress · Chapter 12 · Code Sample 12.B

Collects and validates standardised model metadata for inclusion
in a model card. Enforces presence of required fields before a
card can be marked as ready for publication.

Required fields (card cannot be finalised without these):
  model_name, version, architecture, task_type, training_framework,
  primary_contact, license

Recommended fields (warning if absent):
  dataset_references, training_date, compute_description,
  intended_use, out_of_scope_use
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


_REQUIRED_FIELDS = {
    "model_name", "version", "architecture", "task_type",
    "training_framework", "primary_contact", "license",
}

_RECOMMENDED_FIELDS = {
    "dataset_references", "training_date", "compute_description",
    "intended_use", "out_of_scope_use",
}

_KNOWN_TASK_TYPES = {
    "text-classification", "token-classification", "text-generation",
    "question-answering", "summarisation", "translation",
    "image-classification", "object-detection", "image-segmentation",
    "tabular-classification", "tabular-regression", "time-series-forecasting",
    "anomaly-detection", "recommendation", "reinforcement-learning", "other",
}


@dataclass
class ModelMetadata:
    # Required
    model_name:          str = ""
    version:             str = ""
    architecture:        str = ""
    task_type:           str = ""
    training_framework:  str = ""
    primary_contact:     str = ""
    license:             str = ""
    # Recommended
    dataset_references:  List[str] = field(default_factory=list)
    training_date:       str = ""
    compute_description: str = ""
    intended_use:        str = ""
    out_of_scope_use:    str = ""
    # Optional
    base_model:          str = ""
    fine_tuned_from:     str = ""
    languages:           List[str] = field(default_factory=list)
    tags:                List[str] = field(default_factory=list)
    paper_url:           str = ""
    repository_url:      str = ""
    extra:               Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


@dataclass
class MetadataValidationResult:
    valid:            bool
    missing_required: List[str]
    missing_recommended: List[str]
    warnings:         List[str]

    def summary(self) -> str:
        if self.valid:
            warns = f" ({len(self.missing_recommended)} recommended fields missing)" \
                    if self.missing_recommended else ""
            return f"✅ Metadata valid{warns}."
        return (f"❌ Metadata invalid — missing required: "
                f"{', '.join(self.missing_required)}")


class MetadataExtractor:
    """
    Collects and validates model metadata for model card generation.
    """

    def build(self, **kwargs) -> ModelMetadata:
        """Build a ModelMetadata from keyword arguments."""
        valid_fields = {f.name for f in ModelMetadata.__dataclass_fields__.values()}
        meta   = ModelMetadata()
        extras = {}
        for k, v in kwargs.items():
            if k in valid_fields:
                setattr(meta, k, v)
            else:
                extras[k] = v
        meta.extra = extras
        return meta

    def from_dict(self, data: dict) -> ModelMetadata:
        return self.build(**data)

    def from_json(self, path: str | Path) -> ModelMetadata:
        return self.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def validate(self, meta: ModelMetadata) -> MetadataValidationResult:
        d = meta.to_dict()
        missing_req  = [f for f in _REQUIRED_FIELDS   if not d.get(f)]
        missing_rec  = [f for f in _RECOMMENDED_FIELDS if not d.get(f)]
        warnings: List[str] = []

        if meta.task_type and meta.task_type not in _KNOWN_TASK_TYPES:
            warnings.append(
                f"task_type '{meta.task_type}' is not in the known list. "
                f"Known: {sorted(_KNOWN_TASK_TYPES)}"
            )
        if meta.license and meta.license.lower() == "proprietary" and not meta.primary_contact:
            warnings.append("Proprietary license should have a primary_contact set.")

        return MetadataValidationResult(
            valid             = len(missing_req) == 0,
            missing_required  = missing_req,
            missing_recommended = missing_rec,
            warnings          = warnings,
        )
