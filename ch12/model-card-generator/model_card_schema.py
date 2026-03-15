"""
model_card_schema.py  —  Model card assembly and serialisation
AI Fortress · Chapter 12 · Code Sample 12.B

Assembles all model card sections into a single ModelCard object
and serialises to JSON (machine-readable) and Markdown (human-readable).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from metadata_extractor import ModelMetadata, MetadataExtractor
from risk_bias_documenter import RiskBiasDocument
from evaluation_formatter import EvaluationReport


@dataclass
class ModelCard:
    card_id:     str
    created_at:  str
    version:     str         # card schema version
    metadata:    ModelMetadata
    risk:        Optional[RiskBiasDocument]
    evaluation:  Optional[EvaluationReport]
    finalised:   bool = False
    finalised_at: str = ""
    finalised_by: str = ""

    def to_dict(self) -> dict:
        import dataclasses
        d = dataclasses.asdict(self)
        return d

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )

    def to_markdown(self) -> str:
        md = [
            f"# Model Card: {self.metadata.model_name} v{self.metadata.version}",
            f"\n_Generated: {self.created_at}_\n",
            "## Model Details",
            f"- **Architecture**: {self.metadata.architecture}",
            f"- **Task**: {self.metadata.task_type}",
            f"- **Framework**: {self.metadata.training_framework}",
            f"- **License**: {self.metadata.license}",
            f"- **Contact**: {self.metadata.primary_contact}",
        ]
        if self.metadata.intended_use:
            md += ["\n## Intended Use", self.metadata.intended_use]
        if self.metadata.out_of_scope_use:
            md += ["\n## Out-of-Scope Use", self.metadata.out_of_scope_use]
        if self.metadata.dataset_references:
            md += ["\n## Training Data"]
            for ds in self.metadata.dataset_references:
                md.append(f"- {ds}")
        if self.risk:
            md += [
                "\n## Risk & Bias",
                f"**EU AI Act tier**: {self.risk.eu_ai_act_tier}",
                f"_{self.risk.eu_ai_act_reason}_",
            ]
            if self.risk.known_limitations:
                md.append("\n### Known Limitations")
                for lim in self.risk.known_limitations:
                    md.append(f"- {lim}")
            if self.risk.bias_findings:
                md.append("\n### Bias Findings")
                for bf in self.risk.bias_findings:
                    md.append(
                        f"- **{bf.dimension}** ({bf.severity}): "
                        f"{bf.description}"
                        + (f" Mitigation: {bf.mitigation}" if bf.mitigation else "")
                    )
        if self.evaluation:
            md += ["\n## Evaluation Results", self.evaluation.summary_table()]
            if self.evaluation.performance_gaps:
                md.append("\n### Performance Gaps")
                for gap in self.evaluation.performance_gaps:
                    md.append(
                        f"- **{gap.dimension}** — {gap.metric} on {gap.dataset}: "
                        f"gap={gap.gap:.3f} ({gap.severity}) "
                        f"[best: {gap.best_slice}={gap.best_value:.3f}, "
                        f"worst: {gap.worst_slice}={gap.worst_value:.3f}]"
                    )
        if self.finalised:
            md += [
                f"\n---\n_Finalised by {self.finalised_by} at {self.finalised_at}_"
            ]
        return "\n".join(md) + "\n"

    def save_markdown(self, path: str | Path) -> None:
        Path(path).write_text(self.to_markdown(), encoding="utf-8")


class ModelCardBuilder:
    """
    Assembles and validates a ModelCard from its component sections.
    """

    SCHEMA_VERSION = "1.0"

    def __init__(self):
        self._metadata:   Optional[ModelMetadata]    = None
        self._risk:       Optional[RiskBiasDocument] = None
        self._evaluation: Optional[EvaluationReport] = None

    def with_metadata(self, meta: ModelMetadata) -> "ModelCardBuilder":
        self._metadata = meta
        return self

    def with_risk(self, risk: RiskBiasDocument) -> "ModelCardBuilder":
        self._risk = risk
        return self

    def with_evaluation(self, eval_report: EvaluationReport) -> "ModelCardBuilder":
        self._evaluation = eval_report
        return self

    def build(self) -> ModelCard:
        if self._metadata is None:
            raise ValueError("ModelCard requires metadata. Call with_metadata() first.")
        extractor = MetadataExtractor()
        val = extractor.validate(self._metadata)
        if not val.valid:
            raise ValueError(
                f"Metadata validation failed: missing required fields "
                f"{val.missing_required}"
            )
        return ModelCard(
            card_id    = str(uuid.uuid4()),
            created_at = datetime.now(timezone.utc).isoformat(),
            version    = self.SCHEMA_VERSION,
            metadata   = self._metadata,
            risk       = self._risk,
            evaluation = self._evaluation,
        )

    def finalise(self, card: ModelCard, finalised_by: str) -> ModelCard:
        card.finalised    = True
        card.finalised_at = datetime.now(timezone.utc).isoformat()
        card.finalised_by = finalised_by
        return card
