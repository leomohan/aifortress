"""
privacy_parameter_selector.py  —  DP parameter recommendation
AI Fortress · Chapter 13 · Code Sample 13.C

Recommends (ε, δ) settings and noise scale for DP synthetic data
given dataset characteristics and a desired utility target.

Rules of thumb used (from literature):
  ε < 1    — strong privacy, low utility for small N
  1 ≤ ε < 10 — moderate privacy, acceptable utility for N > 1,000
  ε ≥ 10   — weak privacy; use only for N > 100,000 or low-sensitivity data
  δ = 1/N² — standard choice for δ (much less than 1/N)
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List


@dataclass
class ParameterRecommendation:
    epsilon:           float
    delta:             float
    noise_scale:       float       # σ for mean sensitivity = 1
    privacy_level:     str         # "strong" | "moderate" | "weak"
    utility_note:      str
    warnings:          List[str]


class PrivacyParameterSelector:
    """
    Recommends (ε, δ) privacy parameters for DP synthetic data.
    """

    def recommend(
        self,
        n_records:           int,
        sensitivity:         float = 1.0,  # max sensitivity of statistics
        desired_utility:     str   = "moderate",  # "high" | "moderate" | "low"
        regulatory_context:  str   = "gdpr",      # "gdpr" | "hipaa" | "internal"
    ) -> ParameterRecommendation:
        warnings: List[str] = []

        if n_records < 100:
            warnings.append(
                f"Very small dataset (N={n_records}). "
                "DP synthetic data will have very low fidelity. "
                "Consider increasing dataset size or using aggregation only."
            )

        if regulatory_context == "hipaa" and desired_utility == "high":
            warnings.append(
                "HIPAA de-identification may require ε < 1 for strong DP guarantee."
            )

        # Select epsilon based on size and utility target
        if desired_utility == "high":
            if n_records >= 100_000:
                epsilon = 8.0
            elif n_records >= 10_000:
                epsilon = 4.0
            else:
                epsilon = 2.0
                warnings.append(
                    f"High utility with N={n_records} requires ε={epsilon}; "
                    "privacy guarantee is limited."
                )
        elif desired_utility == "moderate":
            epsilon = 1.0 if n_records >= 10_000 else 2.0
        else:  # "low" utility = strong privacy
            epsilon = 0.1

        # GDPR / regulatory adjustment
        if regulatory_context == "gdpr" and epsilon > 5.0:
            warnings.append("ε > 5 may not satisfy GDPR Article 89 anonymisation standard.")

        delta         = 1.0 / (n_records ** 2)
        noise_scale   = math.sqrt(2 * math.log(1.25 / delta)) / epsilon * sensitivity
        privacy_level = "strong" if epsilon < 1 else "moderate" if epsilon < 10 else "weak"
        utility_note  = (
            f"Expected mean error ≈ {noise_scale:.4f} (noise scale × sensitivity). "
            f"Fidelity improves with larger N."
        )

        return ParameterRecommendation(
            epsilon       = epsilon,
            delta         = delta,
            noise_scale   = round(noise_scale, 6),
            privacy_level = privacy_level,
            utility_note  = utility_note,
            warnings      = warnings,
        )
