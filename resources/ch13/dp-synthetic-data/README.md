# Ch.13-C — Differentially Private Synthetic Data

**AI Fortress** · Chapter 13: Privacy-Preserving Machine Learning

---

## What This Does

Generates differentially private synthetic tabular data:

- **Gaussian mechanism synthesiser** — adds calibrated Gaussian noise
  to marginal statistics (column means and covariances) then samples
  synthetic records from the noisy distribution; provides (ε, δ)-DP
  guarantees on the released statistics
- **Privacy parameter selector** — given a dataset size N and a desired
  utility target, recommends (ε, δ) settings and noise scale; balances
  privacy / utility trade-off using empirical rules of thumb
- **Fidelity evaluator** — measures statistical fidelity of synthetic
  data vs original: per-column mean error, std dev error, correlation
  matrix distance, and marginal distribution overlap (via histogram
  intersection)

---

## File Structure

```
dp-synthetic-data/
├── README.md
├── requirements.txt
├── gaussian_synthesiser.py     # DP tabular synthesiser via noisy statistics
├── privacy_parameter_selector.py # (ε, δ) parameter recommendation
├── fidelity_evaluator.py       # Synthetic vs real fidelity metrics
└── tests/
    └── test_synthetic.py
```
