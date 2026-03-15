"""
robustness_evaluator.py  —  End-to-end robustness evaluation pipeline
AI Fortress · Chapter 5 · Code Sample 5.B

Runs a complete robustness evaluation across a test dataset:

  1. Clean accuracy          — baseline model accuracy on unperturbed inputs
  2. FGSM accuracy           — accuracy after FGSM attack (ε budget)
  3. PGD accuracy            — accuracy after PGD attack (stronger)
  4. Defence detection rate  — fraction of adversarial examples caught by the
                               defence pipeline (smoothing + squeezing)
  5. Certified radius stats  — distribution of certified radii from randomised
                               smoothing (mean, median, % abstained)
  6. False positive rate     — fraction of clean inputs incorrectly flagged

Outputs a structured RobustnessReport that can be embedded in an MMSR
(Chapter 4 Resource 4.C) as part of the model security evidence package.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import numpy as np

from attack_simulator import AdversarialAttackSimulator
from feature_squeezer import FeatureSqueezer
from input_smoothing import RandomisedSmoother, ABSTAIN


@dataclass
class RobustnessReport:
    n_samples:              int
    clean_accuracy:         float
    fgsm_accuracy:          float
    pgd_accuracy:           float
    fgsm_attack_success:    float    # fraction where FGSM flipped prediction
    pgd_attack_success:     float
    defence_detection_rate: float    # fraction of successful attacks caught by defence
    false_positive_rate:    float    # fraction of clean inputs flagged as adversarial
    certified_radius_mean:  float
    certified_radius_median: float
    abstain_rate:           float    # fraction of inputs where smoother abstains
    epsilon:                float
    sigma:                  float
    security_verdict:       str      # "PASS" | "WARN" | "FAIL"
    details:                dict = field(default_factory=dict)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def summary_md(self) -> str:
        icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}[self.security_verdict]
        return (
            f"## Adversarial Robustness Report {icon} ({self.security_verdict})\n\n"
            f"| Metric | Value |\n|--------|-------|\n"
            f"| Clean Accuracy | {self.clean_accuracy:.1%} |\n"
            f"| FGSM Accuracy (ε={self.epsilon:.4f}) | {self.fgsm_accuracy:.1%} |\n"
            f"| PGD Accuracy | {self.pgd_accuracy:.1%} |\n"
            f"| Defence Detection Rate | {self.defence_detection_rate:.1%} |\n"
            f"| False Positive Rate | {self.false_positive_rate:.1%} |\n"
            f"| Cert. Radius (mean) | {self.certified_radius_mean:.4f} |\n"
            f"| Abstain Rate | {self.abstain_rate:.1%} |\n"
        )


class RobustnessEvaluator:
    """
    Evaluates model robustness against adversarial attacks and defence pipelines.

    Parameters
    ----------
    score_fn      : Callable mapping a numpy array to a score/prob vector.
    epsilon       : ℓ∞ perturbation budget for attacks.
    sigma         : Gaussian noise σ for randomised smoothing.
    n_smooth      : Samples per prediction for smoothing (default 50 for speed).
    pgd_steps     : PGD iterations (default 10 for evaluation speed).
    """

    def __init__(
        self,
        score_fn:   Callable[[np.ndarray], np.ndarray],
        epsilon:    float = 8 / 255,
        sigma:      float = 0.25,
        n_smooth:   int   = 50,
        pgd_steps:  int   = 10,
    ):
        self.score_fn = score_fn
        self.epsilon  = epsilon
        self.sigma    = sigma
        self.attacker = AdversarialAttackSimulator(epsilon=epsilon)
        self.smoother = RandomisedSmoother(sigma=sigma, n_samples=n_smooth)
        self.squeezer = FeatureSqueezer(bit_depth=4, spatial_smoothing=True)
        self.pgd_steps = pgd_steps

    def evaluate(
        self,
        test_inputs:  List[np.ndarray],
        test_labels:  List[int],
        calibrate_squeezer: bool = True,
    ) -> RobustnessReport:
        """
        Run full robustness evaluation on (input, label) pairs.
        """
        n = len(test_inputs)
        assert n == len(test_labels), "Inputs and labels must be same length"

        # Calibrate squeezer threshold on clean data
        if calibrate_squeezer and n >= 5:
            self.squeezer.calibrate(test_inputs[:max(5, n // 5)], self.score_fn)

        # ── Per-sample evaluation ─────────────────────────────────────────
        clean_correct      = 0
        fgsm_correct       = 0
        pgd_correct        = 0
        fgsm_successes     = 0
        pgd_successes      = 0
        defence_caught     = 0
        adv_total          = 0
        fp_count           = 0
        radii: List[float] = []
        abstain_count      = 0

        for x, y in zip(test_inputs, test_labels):
            # Clean accuracy
            scores    = np.asarray(self.score_fn(x), dtype=float)
            pred_clean = int(np.argmax(scores))
            if pred_clean == y:
                clean_correct += 1

            # FGSM attack
            fgsm_result = self.attacker.fgsm(x, self.score_fn)
            if fgsm_result.adversarial_class == y:
                fgsm_correct += 1
            if fgsm_result.success:
                fgsm_successes += 1
                adv_total += 1
                # Defence check
                sq_res = self.squeezer.detect(fgsm_result.adversarial, self.score_fn)
                if sq_res.is_adversarial:
                    defence_caught += 1

            # PGD attack
            pgd_result = self.attacker.pgd(x, self.score_fn, n_steps=self.pgd_steps)
            if pgd_result.adversarial_class == y:
                pgd_correct += 1
            if pgd_result.success:
                pgd_successes += 1
                adv_total += 1
                sq_res = self.squeezer.detect(pgd_result.adversarial, self.score_fn)
                if sq_res.is_adversarial:
                    defence_caught += 1

            # False positive rate (flag clean input as adversarial)
            sq_clean = self.squeezer.detect(x, self.score_fn)
            if sq_clean.is_adversarial:
                fp_count += 1

            # Certified radius
            smooth_res = self.smoother.predict_and_certify(x, self.score_fn)
            if smooth_res.abstained:
                abstain_count += 1
            else:
                radii.append(smooth_res.certified_radius)

        # ── Aggregate ─────────────────────────────────────────────────────
        clean_acc      = clean_correct / n
        fgsm_acc       = fgsm_correct  / n
        pgd_acc        = pgd_correct   / n
        fgsm_success_r = fgsm_successes / n
        pgd_success_r  = pgd_successes  / n
        det_rate       = defence_caught / adv_total if adv_total > 0 else 0.0
        fpr            = fp_count / n
        r_mean         = float(np.mean(radii)) if radii else 0.0
        r_med          = float(np.median(radii)) if radii else 0.0
        abstain_rate   = abstain_count / n

        # Security verdict
        if fgsm_acc >= 0.70 and det_rate >= 0.80 and fpr <= 0.10:
            verdict = "PASS"
        elif fgsm_acc >= 0.50 and det_rate >= 0.60:
            verdict = "WARN"
        else:
            verdict = "FAIL"

        return RobustnessReport(
            n_samples              = n,
            clean_accuracy         = round(clean_acc,     4),
            fgsm_accuracy          = round(fgsm_acc,      4),
            pgd_accuracy           = round(pgd_acc,       4),
            fgsm_attack_success    = round(fgsm_success_r, 4),
            pgd_attack_success     = round(pgd_success_r,  4),
            defence_detection_rate = round(det_rate,       4),
            false_positive_rate    = round(fpr,            4),
            certified_radius_mean  = round(r_mean,         4),
            certified_radius_median = round(r_med,         4),
            abstain_rate           = round(abstain_rate,   4),
            epsilon                = self.epsilon,
            sigma                  = self.sigma,
            security_verdict       = verdict,
        )
