"""
golden_set_validator.py  —  Golden-set comparison and annotator trust scoring
AI Fortress · Chapter 3 · Code Sample 3.B

Compares submitted labels against a trusted golden reference set.
Produces:
  - Overall accuracy, precision, recall, F1 per class
  - Per-annotator trust score (weighted F1 on their golden-set submissions)
  - Confusion matrix summary
  - Recommended re-annotation targets (worst-performing classes / annotators)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    cohen_kappa_score,
    confusion_matrix,
)


@dataclass
class GoldenValidationResult:
    accuracy:           float
    weighted_f1:        float
    per_class_metrics:  Dict[str, dict]    # class → {precision, recall, f1, support}
    confusion_matrix:   List[List[int]]
    classes:            List[str]
    n_compared:         int
    details:            dict = field(default_factory=dict)


@dataclass
class AnnotatorTrustScore:
    annotator_id: str
    trust_score:  float          # weighted F1 on golden set
    n_gold_submitted: int
    accuracy:     float
    weak_classes: List[str]      # classes with F1 < 0.7


class GoldenSetValidator:
    """
    Validates labels against a golden reference set and scores annotators.

    Parameters
    ----------
    min_gold_submissions : Minimum golden-set submissions required to score an annotator
    weak_class_f1_threshold : F1 below which a class is flagged as "weak" for an annotator
    """

    def __init__(
        self,
        min_gold_submissions:    int   = 10,
        weak_class_f1_threshold: float = 0.70,
    ):
        self.min_gold_submissions    = min_gold_submissions
        self.weak_class_f1_threshold = weak_class_f1_threshold

    def validate(
        self,
        predicted: pd.Series,
        golden:    pd.Series,
    ) -> GoldenValidationResult:
        """
        Compare predicted labels to golden labels.

        Parameters
        ----------
        predicted : Labels to validate (from annotators / model)
        golden    : Trusted ground-truth labels
        """
        df = pd.DataFrame({"pred": predicted, "gold": golden}).dropna()
        if len(df) == 0:
            raise ValueError("No overlapping non-null labels to compare")

        y_pred = df["pred"].values
        y_true = df["gold"].values
        classes = sorted(set(y_true) | set(y_pred))

        acc  = float((y_pred == y_true).mean())
        cm   = confusion_matrix(y_true, y_pred, labels=classes).tolist()
        report = classification_report(y_true, y_pred, labels=classes,
                                       output_dict=True, zero_division=0)

        per_class: Dict[str, dict] = {}
        for cls in classes:
            cls_str = str(cls)
            r = report.get(cls_str, {})
            per_class[cls_str] = {
                "precision": round(r.get("precision", 0.0), 4),
                "recall":    round(r.get("recall", 0.0), 4),
                "f1":        round(r.get("f1-score", 0.0), 4),
                "support":   int(r.get("support", 0)),
            }

        wf1 = round(float(report.get("weighted avg", {}).get("f1-score", 0.0)), 4)

        return GoldenValidationResult(
            accuracy           = round(acc, 4),
            weighted_f1        = wf1,
            per_class_metrics  = per_class,
            confusion_matrix   = cm,
            classes            = [str(c) for c in classes],
            n_compared         = len(df),
            details            = {
                "kappa": round(float(cohen_kappa_score(y_true, y_pred)), 4)
                         if len(set(y_true)) > 1 else None,
            },
        )

    def score_annotators(
        self,
        annotations_df:  pd.DataFrame,
        golden_df:       pd.DataFrame,
        annotator_col:   str,
        item_id_col:     str,
        label_col:       str,
        golden_label_col: str = "true_label",
    ) -> List[AnnotatorTrustScore]:
        """
        Score each annotator against the golden set.

        Parameters
        ----------
        annotations_df   : DataFrame with columns [annotator_col, item_id_col, label_col]
        golden_df        : DataFrame with columns [item_id_col, golden_label_col]
        """
        merged = annotations_df.merge(golden_df, on=item_id_col, how="inner")
        if len(merged) == 0:
            return []

        scores: List[AnnotatorTrustScore] = []
        for annotator_id, group in merged.groupby(annotator_col):
            if len(group) < self.min_gold_submissions:
                continue

            y_pred = group[label_col].values
            y_true = group[golden_label_col].values
            classes = sorted(set(y_true))

            acc     = float((y_pred == y_true).mean())
            report  = classification_report(y_true, y_pred, labels=classes,
                                            output_dict=True, zero_division=0)
            wf1     = float(report.get("weighted avg", {}).get("f1-score", 0.0))

            weak = [
                str(cls) for cls in classes
                if report.get(str(cls), {}).get("f1-score", 1.0) < self.weak_class_f1_threshold
            ]

            scores.append(AnnotatorTrustScore(
                annotator_id     = str(annotator_id),
                trust_score      = round(wf1, 4),
                n_gold_submitted = len(group),
                accuracy         = round(acc, 4),
                weak_classes     = weak,
            ))

        return sorted(scores, key=lambda s: s.trust_score)
