"""
tests/test_label_validation.py  —  Label validation pipeline tests
AI Fortress · Chapter 3 · Code Sample 3.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import numpy as np
import pandas as pd
import pytest
from iaa_calculator import IAACalculator
from confidence_cleaner import ConfidenceCleaner
from noise_rate_estimator import NoiseRateEstimator
from golden_set_validator import GoldenSetValidator


def _make_features_labels(n=300, noise=0.05, seed=42):
    rng = np.random.default_rng(seed)
    X = np.hstack([
        rng.normal(0, 1, (n, 2)),
        rng.normal(3, 1, (n, 2)),
    ]).reshape(n, 4)
    # Simple linear-separable labels
    y = np.array(["cat"] * (n // 2) + ["dog"] * (n - n // 2))
    # Inject noise
    n_noisy = int(n * noise)
    noisy_idx = rng.choice(n, n_noisy, replace=False)
    y[noisy_idx] = np.where(y[noisy_idx] == "cat", "dog", "cat")
    return X, y


class TestIAACalculator:
    def test_cohens_kappa_perfect(self):
        labels = pd.Series(["cat","dog","cat","dog","cat"])
        result = IAACalculator().cohens_kappa(labels, labels)
        assert result.value == pytest.approx(1.0, abs=0.01)
        assert "perfect" in result.interpretation.lower()

    def test_cohens_kappa_random(self):
        rng = np.random.default_rng(0)
        a = pd.Series(rng.choice(["cat","dog"], 200))
        b = pd.Series(rng.choice(["cat","dog"], 200))
        result = IAACalculator().cohens_kappa(a, b)
        assert -1.0 <= result.value <= 1.0

    def test_fleiss_kappa(self):
        # 5 subjects, 3 categories, 3 raters each
        ratings = np.array([
            [3, 0, 0],
            [0, 3, 0],
            [0, 0, 3],
            [2, 1, 0],
            [1, 1, 1],
        ])
        result = IAACalculator().fleiss_kappa(ratings)
        assert -1.0 <= result.value <= 1.0

    def test_krippendorffs_alpha_perfect(self):
        # All annotators agree
        data = [[1, 2, 1, 2, 1], [1, 2, 1, 2, 1], [1, 2, 1, 2, 1]]
        result = IAACalculator().krippendorffs_alpha(data, "nominal")
        assert result.value == pytest.approx(1.0, abs=0.01)

    def test_annotator_disagreement_report(self):
        df = pd.DataFrame({
            "ann1": ["cat","dog","cat","dog","cat"],
            "ann2": ["cat","cat","cat","dog","dog"],   # disagrees on items 1,4
            "ann3": ["cat","dog","cat","cat","cat"],
        })
        report = IAACalculator().annotator_disagreement_report(df, ["ann1","ann2","ann3"])
        assert 0.0 <= report["mean_agreement"] <= 1.0
        assert report["n_total"] == 5


class TestConfidenceCleaner:
    def test_finds_noisy_labels(self):
        X, y = _make_features_labels(n=300, noise=0.10)
        result = ConfidenceCleaner(n_splits=3).find_noisy_labels(X, y)
        assert result.n_samples == 300
        assert 0 <= result.noise_rate <= 1.0
        assert isinstance(result.noisy_indices, list)

    def test_clean_data_low_noise_rate(self):
        X, y = _make_features_labels(n=300, noise=0.0)
        result = ConfidenceCleaner(n_splits=3).find_noisy_labels(X, y)
        # Clean data should have low flagged rate
        assert result.noise_rate < 0.20   # generous threshold

    def test_clean_dataframe(self):
        X, y = _make_features_labels(n=200, noise=0.05)
        df = pd.DataFrame(X, columns=["f1","f2","f3","f4"])
        df["label"] = y
        cleaned, result = ConfidenceCleaner(n_splits=3).clean_dataframe(
            df, ["f1","f2","f3","f4"], "label"
        )
        assert len(cleaned) == result.n_samples - len(result.noisy_indices)


class TestNoiseRateEstimator:
    def test_returns_valid_rates(self):
        X, y = _make_features_labels(n=300, noise=0.08)
        result = NoiseRateEstimator(n_splits=3).estimate(X, y)
        assert 0.0 <= result.global_noise_rate <= 1.0
        assert "cat" in result.per_class_noise
        assert "dog" in result.per_class_noise
        assert len(result.transition_matrix) == 2

    def test_clean_data_low_noise(self):
        X, y = _make_features_labels(n=300, noise=0.0)
        result = NoiseRateEstimator(n_splits=3).estimate(X, y)
        assert result.global_noise_rate < 0.30   # generous threshold for estimator


class TestGoldenSetValidator:
    def test_perfect_labels(self):
        labels = pd.Series(["cat","dog","cat","dog","cat"])
        result = GoldenSetValidator().validate(labels, labels)
        assert result.accuracy == pytest.approx(1.0)
        assert result.weighted_f1 == pytest.approx(1.0)

    def test_imperfect_labels(self):
        pred   = pd.Series(["cat","dog","cat","dog","cat"])
        golden = pd.Series(["cat","cat","cat","dog","dog"])
        result = GoldenSetValidator().validate(pred, golden)
        assert 0.0 < result.accuracy < 1.0
        assert "cat" in result.per_class_metrics
        assert "dog" in result.per_class_metrics

    def test_annotator_scoring(self):
        ann = pd.DataFrame({
            "annotator": ["A"]*10 + ["B"]*10,
            "item_id":   list(range(10)) + list(range(10)),
            "label":     ["cat"]*10 + ["cat","dog","cat","dog","cat","dog","cat","dog","cat","dog"],
        })
        gold = pd.DataFrame({
            "item_id":    list(range(10)),
            "true_label": ["cat","cat","cat","cat","cat","cat","cat","cat","cat","cat"],
        })
        scores = GoldenSetValidator(min_gold_submissions=5).score_annotators(
            ann, gold, "annotator", "item_id", "label"
        )
        assert len(scores) == 2
        # Annotator A (all cat) should score higher than B (mixed)
        score_a = next(s for s in scores if s.annotator_id == "A")
        score_b = next(s for s in scores if s.annotator_id == "B")
        assert score_a.trust_score > score_b.trust_score
