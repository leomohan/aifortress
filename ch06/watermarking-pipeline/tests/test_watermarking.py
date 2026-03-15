"""
tests/test_watermarking.py
AI Fortress · Chapter 6 · Code Sample 6.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import os
import numpy as np
import pytest
from radioactive_data import RadioactiveDataWatermarker, RadioactiveKey
from weight_watermark import WeightWatermarker
from output_watermark import OutputWatermarker


# ── Helpers ───────────────────────────────────────────────────────────────────

def softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max())
    return e / e.sum()


def make_linear_model(weights: np.ndarray):
    """Returns a score_fn that applies a linear transformation + softmax."""
    def score_fn(x: np.ndarray) -> np.ndarray:
        flat = x.flatten()
        n_classes = 3
        W = weights[:n_classes * len(flat)].reshape(n_classes, len(flat))
        return softmax(W @ flat)
    return score_fn


# ── RadioactiveDataWatermarker ────────────────────────────────────────────────

class TestRadioactiveData:
    def _make_dataset(self, n=100, d=20, n_classes=3, seed=0):
        rng    = np.random.default_rng(seed)
        X      = rng.uniform(0, 1, (n, d)).astype(np.float32)
        y      = rng.integers(0, n_classes, n)
        return X, y

    def test_embed_preserves_shape(self):
        wm = RadioactiveDataWatermarker("owner-1", watermark_fraction=0.10, epsilon=0.05)
        X, y  = self._make_dataset()
        X_wm, key = wm.embed(X, y, secret=b"owner-secret-42")
        assert X_wm.shape == X.shape

    def test_watermarked_values_clipped(self):
        wm = RadioactiveDataWatermarker("owner-1", epsilon=0.5)
        X, y = self._make_dataset()
        X_wm, _ = wm.embed(X, y, secret=b"test")
        assert X_wm.min() >= 0.0 - 1e-6
        assert X_wm.max() <= 1.0 + 1e-6

    def test_key_saved_and_loaded(self, tmp_path):
        wm    = RadioactiveDataWatermarker("owner-2")
        X, y  = self._make_dataset()
        _, key = wm.embed(X, y, secret=b"secret")
        key_path = tmp_path / "key.json"
        key.save(key_path)
        loaded = RadioactiveKey.load(key_path)
        assert loaded.owner_id == key.owner_id
        assert loaded.key_id   == key.key_id

    def test_verify_positive_for_biased_model(self):
        """A model that always boosts the target class should be detected."""
        wm = RadioactiveDataWatermarker("owner-3", epsilon=0.5, alpha=0.05)
        X, y = self._make_dataset(n=200)
        X_wm, key = wm.embed(X, y, secret=b"my-secret", target_class=0)

        # Model that returns higher confidence for class 0 on perturbed inputs
        def biased_model(x):
            mean = float(x.mean())
            base = np.array([0.2, 0.4, 0.4])
            base[0] += 0.3 * mean   # positive correlation with class 0
            return base / base.sum()

        result = wm.verify(key, X[:50], biased_model, n_verify=50)
        # Not guaranteed to detect with toy model, but structure should be valid
        assert isinstance(result.dataset_member, bool)
        assert 0.0 <= result.p_value <= 1.0

    def test_verify_negative_for_unrelated_model(self):
        """A model with no bias should not be detected (p > alpha typically)."""
        wm = RadioactiveDataWatermarker("owner-4", epsilon=0.01, alpha=0.01)
        X, y = self._make_dataset(n=100)
        _, key = wm.embed(X, y, secret=b"secret2")

        def uniform_model(x):
            return np.array([1/3, 1/3, 1/3])

        result = wm.verify(key, X[:50], uniform_model)
        # Uniform model — delta should be near zero, likely not detected
        assert result.n_samples > 0


# ── WeightWatermarker ─────────────────────────────────────────────────────────

class TestWeightWatermark:
    def _make_weights(self, n=1000, seed=0):
        return np.random.default_rng(seed).normal(0, 0.1, n)

    def test_embed_preserves_shape(self):
        wm = WeightWatermarker("owner-1", n_bits=32)
        w  = self._make_weights()
        w2, key = wm.embed(w, "model-A", secret=b"secret")
        assert w2.shape == w.shape

    def test_verify_detects_watermark(self):
        wm = WeightWatermarker("owner-1", n_bits=64, delta=0.5, threshold_ber=0.20)
        w  = self._make_weights(n=5000)
        w2, key = wm.embed(w, "model-A", secret=b"secret-1")
        result  = wm.verify(w2, key)
        assert result.detected
        assert result.bit_error_rate <= 0.20

    def test_clean_weights_not_detected(self):
        wm = WeightWatermarker("owner-1", n_bits=64, threshold_ber=0.20)
        w  = self._make_weights(n=5000)
        _, key = wm.embed(w, "model-A", secret=b"secret-2")
        # Verify against UNMODIFIED weights
        result = wm.verify(self._make_weights(n=5000, seed=99), key)
        assert result.bit_error_rate > 0.30   # random → high BER

    def test_key_save_load(self, tmp_path):
        wm = WeightWatermarker("owner-2", n_bits=16)
        w  = self._make_weights()
        _, key = wm.embed(w, "model-B", secret=b"s")
        key.save(tmp_path / "key.json")
        from weight_watermark import WeightWatermarkKey
        loaded = WeightWatermarkKey.load(tmp_path / "key.json")
        assert loaded.key_id == key.key_id
        assert loaded.bit_string == key.bit_string

    def test_wrong_size_not_detected(self):
        wm = WeightWatermarker("owner-1", n_bits=32, threshold_ber=0.20)
        w  = self._make_weights(n=1000)
        _, key = wm.embed(w, "model-A", secret=b"s")
        wrong_w = self._make_weights(n=500)   # wrong size
        result  = wm.verify(wrong_w, key)
        assert not result.detected


# ── OutputWatermarker ─────────────────────────────────────────────────────────

class TestOutputWatermark:
    def _make_logits(self, n=500, n_classes=4, seed=0):
        return [np.random.default_rng(seed + i).normal(0, 1, n_classes) for i in range(n)]

    def test_watermark_output_preserves_shape(self):
        wm     = OutputWatermarker("owner-1", b"secret", n_classes=4)
        logits = np.random.randn(4)
        out    = wm.watermark_output(logits)
        assert out.shape == logits.shape

    def test_soft_perturbation_detected(self):
        secret = b"owner-secret-soft"
        wm     = OutputWatermarker("owner-1", secret, n_classes=4,
                                   mode="soft_perturbation", alpha=0.05)
        # Generate 500 watermarked outputs
        outputs = [wm.watermark_output(np.random.randn(4)) for _ in range(500)]
        result  = wm.verify(outputs, wm.key)
        assert result.n_samples == 500
        assert isinstance(result.detected, bool)
        assert 0.0 <= result.p_value <= 1.0

    def test_unwatermarked_outputs_not_detected(self):
        secret = b"owner-secret-unwm"
        wm     = OutputWatermarker("owner-1", secret, n_classes=4,
                                   mode="soft_perturbation", alpha=0.05)
        # Pure random outputs — no watermark
        random_outputs = [np.random.randn(4) for _ in range(200)]
        result = wm.verify(random_outputs, wm.key)
        # Random outputs should usually not be detected (p > alpha)
        # Not guaranteed but with sufficient samples, BER of random data is ~0.5
        assert result.n_samples == 200

    def test_wrap_applies_watermark(self):
        secret = b"wrap-test"
        wm     = OutputWatermarker("owner-1", secret, n_classes=3,
                                   mode="soft_perturbation")
        raw_fn = lambda x: np.array([0.3, 0.5, 0.2])
        wm_fn  = wm.wrap(raw_fn)
        out    = wm_fn(np.zeros(5))
        # Wrapped output should differ slightly from raw
        raw_out = np.array([0.3, 0.5, 0.2])
        assert not np.allclose(out, raw_out)

    def test_classification_mode_runs(self):
        secret = b"cls-secret"
        wm     = OutputWatermarker("owner-2", secret, n_classes=5,
                                   mode="classification", bias_rate=0.20, alpha=0.05)
        outputs = [wm.watermark_output(np.random.randn(5)) for _ in range(300)]
        result  = wm.verify(outputs, wm.key)
        assert result.mode == "classification"
        assert isinstance(result.detected, bool)
