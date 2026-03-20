"""
model_card_scorer.py  —  Model card completeness scoring
AI Fortress · Chapter 8 · Code Sample 8.C

Scores the completeness of a model card against the AI Fortress standard:
25 fields across 5 categories, weighted by governance importance.

Categories and weights:
  1. Identity (5 fields, weight=1.0)   — name, version, type, task, licence
  2. Training Data (5 fields, w=1.5)   — datasets, preprocessing, splits, period, consent
  3. Evaluation (5 fields, w=1.5)      — benchmarks, metrics, limitations, bias eval, fairness
  4. Limitations (5 fields, w=1.2)     — known failures, out-of-scope, risks, mitigations, monitoring
  5. Governance (5 fields, w=2.0)      — owner, contact, review date, intended use, prohibited use

Mandatory fields (missing = automatic FAIL regardless of score):
  name, version, licence, intended_use, prohibited_use, owner
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


_SCHEMA: Dict[str, List[Tuple[str, float, bool]]] = {
    # category: [(field_name, weight, mandatory)]
    "identity": [
        ("name",         1.0, True),
        ("version",      1.0, True),
        ("model_type",   0.8, False),
        ("task",         0.8, False),
        ("licence",      1.0, True),
    ],
    "training_data": [
        ("datasets",         1.5, False),
        ("preprocessing",    1.0, False),
        ("train_val_split",  0.8, False),
        ("training_period",  0.8, False),
        ("data_consent",     1.5, False),
    ],
    "evaluation": [
        ("benchmarks",      1.5, False),
        ("primary_metric",  1.0, False),
        ("known_biases",    1.5, False),
        ("fairness_eval",   1.5, False),
        ("eval_limitations",1.0, False),
    ],
    "limitations": [
        ("known_failures",   1.2, False),
        ("out_of_scope_use", 1.2, False),
        ("risk_level",       1.0, False),
        ("mitigations",      1.0, False),
        ("monitoring",       1.0, False),
    ],
    "governance": [
        ("owner",          2.0, True),
        ("contact",        1.5, False),
        ("review_date",    1.5, False),
        ("intended_use",   2.0, True),
        ("prohibited_use", 2.0, True),
    ],
}


@dataclass
class ModelCardField:
    field_name: str
    category:   str
    present:    bool
    mandatory:  bool
    weight:     float
    value:      str = ""   # truncated preview


@dataclass
class ModelCardScore:
    model_name:      str
    total_score:     float      # 0–100
    category_scores: Dict[str, float]
    fields:          List[ModelCardField]
    mandatory_missing: List[str]
    overall_pass:    bool       # True if score >= threshold AND no mandatory missing

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        missing_str = f" | Missing mandatory: {self.mandatory_missing}" if self.mandatory_missing else ""
        return (
            f"{icon} Model card '{self.model_name}': score={self.total_score:.0f}/100{missing_str}"
        )


class ModelCardScorer:
    """
    Scores a model card dict against the AI Fortress completeness standard.

    Parameters
    ----------
    pass_threshold : Minimum score (0–100) to pass (default 70)
    """

    def __init__(self, pass_threshold: float = 70.0):
        self.threshold = pass_threshold

    def score(self, model_card: dict) -> ModelCardScore:
        """
        Score a model card dict.

        The dict should have fields matching the schema keys (snake_case).
        Non-empty strings, non-empty lists, and truthy values count as present.
        """
        fields:   List[ModelCardField] = []
        cat_scores: Dict[str, float]  = {}
        mandatory_missing: List[str]  = []

        total_weighted_score  = 0.0
        total_possible_score  = 0.0

        for category, field_specs in _SCHEMA.items():
            cat_earned   = 0.0
            cat_possible = 0.0

            for fname, weight, mandatory in field_specs:
                value   = model_card.get(fname)
                present = bool(value) if not isinstance(value, bool) else value

                cat_possible       += weight
                total_possible_score += weight
                if present:
                    cat_earned         += weight
                    total_weighted_score += weight
                elif mandatory:
                    mandatory_missing.append(fname)

                fields.append(ModelCardField(
                    field_name = fname,
                    category   = category,
                    present    = present,
                    mandatory  = mandatory,
                    weight     = weight,
                    value      = str(value or "")[:80],
                ))

            cat_scores[category] = round(100 * cat_earned / cat_possible, 1) if cat_possible else 0.0

        total_score = round(100 * total_weighted_score / total_possible_score, 1) if total_possible_score else 0.0
        overall     = total_score >= self.threshold and len(mandatory_missing) == 0

        return ModelCardScore(
            model_name       = str(model_card.get("name", "unknown")),
            total_score      = total_score,
            category_scores  = cat_scores,
            fields           = fields,
            mandatory_missing = mandatory_missing,
            overall_pass     = overall,
        )

    def score_json_file(self, path: str | Path) -> ModelCardScore:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.score(data)
