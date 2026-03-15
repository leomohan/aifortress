"""
model_card_extension.py  —  ML metadata SBOM extension (CycloneDX)
AI Fortress · Chapter 8 · Code Sample 8.A

Extends a base CycloneDX SBOM with ML-specific metadata:
  - Training dataset provenance (name, version, source URL, licence, SHA-256)
  - Base model lineage (pretrained model name, source registry, version)
  - Fine-tuning framework and version
  - Evaluation benchmark references
  - Model card URL as an externalReference

Adds these as CycloneDX "model" type components and externalReferences
per the CycloneDX Machine Learning BOM extension (cdx:ml).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from sbom_generator import SBOM, SBOMComponent


@dataclass
class DatasetProvenance:
    name:       str
    version:    str
    source_url: str
    licence:    str
    sha256:     str = ""
    record_count: Optional[int] = None


@dataclass
class BaseModelLineage:
    name:         str
    version:      str
    registry:     str            # "huggingface" | "tensorflow_hub" | "pytorch_hub" | "custom"
    registry_url: str
    licence:      str
    sha256:       str = ""


@dataclass
class ModelCardMetadata:
    model_name:       str
    model_version:    str
    model_type:       str            # "classifier" | "generator" | "regressor" | ...
    task:             str            # "text-classification" | "object-detection" | ...
    datasets:         List[DatasetProvenance] = field(default_factory=list)
    base_models:      List[BaseModelLineage]  = field(default_factory=list)
    frameworks:       List[str] = field(default_factory=list)  # e.g. ["torch==2.2.0"]
    benchmarks:       List[dict] = field(default_factory=list) # {"name": ..., "score": ...}
    model_card_url:   str = ""
    limitations:      str = ""
    intended_use:     str = ""


class ModelCardExtension:
    """
    Extends a base SBOM with ML model card metadata.

    Parameters
    ----------
    metadata : ModelCardMetadata describing the model and its lineage
    """

    def __init__(self, metadata: ModelCardMetadata):
        self.meta = metadata

    def extend(self, sbom: SBOM) -> SBOM:
        """
        Inject model card components and references into `sbom`.
        Returns the same SBOM object (mutated in-place) for chaining.
        """
        # Add model component
        model_component = SBOMComponent(
            type        = "machine-learning-model",
            name        = self.meta.model_name,
            version     = self.meta.model_version,
            purl        = f"pkg:generic/{self.meta.model_name.lower()}@{self.meta.model_version}",
            description = f"{self.meta.task} model ({self.meta.model_type})",
            properties  = [
                {"name": "cdx:ml:model-type", "value": self.meta.model_type},
                {"name": "cdx:ml:task",        "value": self.meta.task},
                {"name": "cdx:ml:limitations", "value": self.meta.limitations},
                {"name": "cdx:ml:intended-use","value": self.meta.intended_use},
            ],
            external_references = self._build_ext_refs(),
        )
        sbom.components.insert(0, model_component)

        # Add dataset components
        for ds in self.meta.datasets:
            sbom.components.append(SBOMComponent(
                type     = "data",
                name     = ds.name,
                version  = ds.version,
                purl     = f"pkg:generic/dataset/{ds.name.lower()}@{ds.version}",
                licences = [ds.licence],
                hashes   = {"SHA-256": ds.sha256} if ds.sha256 else {},
                properties = [
                    {"name": "cdx:ml:dataset-source", "value": ds.source_url},
                    {"name": "cdx:ml:record-count",   "value": str(ds.record_count or "unknown")},
                ],
                external_references = [{"type": "website", "url": ds.source_url}] if ds.source_url else [],
            ))

        # Add base model lineage components
        for bm in self.meta.base_models:
            sbom.components.append(SBOMComponent(
                type     = "machine-learning-model",
                name     = bm.name,
                version  = bm.version,
                purl     = f"pkg:{bm.registry}/{bm.name.lower()}@{bm.version}",
                licences = [bm.licence],
                hashes   = {"SHA-256": bm.sha256} if bm.sha256 else {},
                properties = [
                    {"name": "cdx:ml:base-model-registry", "value": bm.registry},
                ],
                external_references = [{"type": "distribution", "url": bm.registry_url}],
            ))

        # Add benchmark metadata to SBOM metadata
        if self.meta.benchmarks:
            sbom.metadata.setdefault("properties", [])
            for bench in self.meta.benchmarks:
                sbom.metadata["properties"].append({
                    "name":  f"cdx:ml:benchmark:{bench.get('name', 'unknown')}",
                    "value": str(bench.get("score", "")),
                })

        return sbom

    def _build_ext_refs(self) -> list:
        refs = []
        if self.meta.model_card_url:
            refs.append({"type": "documentation", "url": self.meta.model_card_url})
        for bench in self.meta.benchmarks:
            if bench.get("url"):
                refs.append({"type": "other", "url": bench["url"],
                             "comment": f"Benchmark: {bench.get('name', '')}"})
        return refs
