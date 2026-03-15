"""
attribute_inference.py  —  Attribute inference risk scoring
AI Fortress · Chapter 13 · Code Sample 13.D

Estimates the risk that an adversary can reconstruct a sensitive
attribute from model predictions, using a correlation-proxy approach.

The risk score is based on:
  - Correlation between the sensitive attribute and model outputs
  - Confidence gap between records with different attribute values
  - Attribute base rate (rare attributes are harder to infer)
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class AttributeInferenceRisk:
    attribute_name:  str
    risk_score:      float     # 0–1; higher = more risk
    severity:        str       # "critical" | "high" | "moderate" | "low"
    confidence_gap:  float     # mean confidence difference between attribute values
    base_rate:       float     # prevalence of the sensitive attribute value
    detail:          str


class AttributeInferenceAuditor:
    """
    Scores attribute inference risk for a sensitive attribute.
    """

    def audit(
        self,
        attribute_name:    str,
        attribute_values:  List[int],      # 0 or 1 for each record
        model_confidences: List[float],    # model max confidence for each record
    ) -> AttributeInferenceRisk:
        """
        Estimate attribute inference risk.

        Parameters
        ----------
        attribute_name    : Name of the sensitive attribute being audited.
        attribute_values  : Binary indicator (1 = sensitive class present).
        model_confidences : Model max confidence for each corresponding record.
        """
        n = len(attribute_values)
        if n != len(model_confidences):
            raise ValueError("attribute_values and model_confidences must have same length")
        if n == 0:
            raise ValueError("Input lists must not be empty")

        pos_confs = [model_confidences[i] for i, v in enumerate(attribute_values) if v == 1]
        neg_confs = [model_confidences[i] for i, v in enumerate(attribute_values) if v == 0]

        base_rate = len(pos_confs) / n

        if not pos_confs or not neg_confs:
            return AttributeInferenceRisk(
                attribute_name  = attribute_name,
                risk_score      = 0.0,
                severity        = "low",
                confidence_gap  = 0.0,
                base_rate       = base_rate,
                detail          = "Only one attribute class present — cannot assess gap.",
            )

        pos_mean = statistics.mean(pos_confs)
        neg_mean = statistics.mean(neg_confs)
        gap      = abs(pos_mean - neg_mean)

        # Risk increases with gap; decreases for extreme base rates (very rare → harder)
        rarity_penalty = 1.0 - abs(base_rate - 0.5) * 2   # 1.0 at 50/50, 0 at 0% or 100%
        risk_score     = min(1.0, gap * rarity_penalty * 2)

        severity = (
            "critical" if risk_score > 0.7 else
            "high"     if risk_score > 0.5 else
            "moderate" if risk_score > 0.3 else
            "low"
        )
        return AttributeInferenceRisk(
            attribute_name = attribute_name,
            risk_score     = round(risk_score, 4),
            severity       = severity,
            confidence_gap = round(gap, 4),
            base_rate      = round(base_rate, 4),
            detail         = (
                f"Confidence gap={gap:.4f} between attribute=1 (mean={pos_mean:.4f}) "
                f"and attribute=0 (mean={neg_mean:.4f}). Base rate={base_rate:.3f}."
            ),
        )
