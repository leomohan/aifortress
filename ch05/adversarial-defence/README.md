# Ch.05-B — Adversarial Defence

**AI Fortress** · Chapter 5: API Hardening & Adversarial Defence

---

## What This Does

Adversarial example detection and certified robustness toolkit for ML inference pipelines:

- **Input smoothing** — randomised smoothing (Cohen et al. 2019): adds Gaussian noise
  to inputs N times, takes majority vote; certifies a robustness radius ℓ₂ around each
  prediction; any adversarial perturbation smaller than the radius is guaranteed to fail
- **Feature squeezing** — reduces input colour depth and applies spatial smoothing before
  inference; if the squeezed prediction disagrees with the original, the input is flagged
  as adversarial; complementary to randomised smoothing, effective against gradient-based attacks
- **Attack simulator** — implements FGSM (Fast Gradient Sign Method) and PGD (Projected
  Gradient Descent) for framework-agnostic red-teaming; accepts a score function and input
  array; produces adversarial perturbations to test your defence pipeline
- **Robustness evaluator** — runs a full robustness evaluation: clean accuracy, accuracy
  under FGSM/PGD attack, detection rate of the defence pipeline, and certified radius
  distribution; outputs a structured robustness report

---

## File Structure

```
adversarial-defence/
├── README.md
├── requirements.txt
├── input_smoothing.py          # Randomised smoothing with certified radius
├── feature_squeezer.py         # Feature squeezing detector
├── attack_simulator.py         # FGSM and PGD attack simulation
├── robustness_evaluator.py     # End-to-end robustness evaluation pipeline
└── tests/
    └── test_adversarial_defence.py
```

## Quick Start

```python
from input_smoothing import RandomisedSmoother
from feature_squeezer import FeatureSqueezer

# Randomised smoothing
smoother = RandomisedSmoother(sigma=0.25, n_samples=100, confidence=0.999)
prediction, certified_radius = smoother.predict_and_certify(
    input_array=x, score_fn=my_model
)
print(f"Prediction: {prediction}, Certified radius: {certified_radius:.3f}")

# Feature squeezing
squeezer = FeatureSqueezer(bit_depth=4, spatial_smoothing=True)
is_adversarial = squeezer.detect(original=x, score_fn=my_model, threshold=0.05)
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
