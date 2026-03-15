# Ch.13-E — Privacy-Preserving Inference

**AI Fortress** · Chapter 13: Privacy-Preserving Machine Learning

---

## What This Does

Applies privacy controls at inference time to limit information leakage
through model predictions:

- **Output perturbation** — adds calibrated Laplace or Gaussian noise
  to model outputs before returning them; noise scale is calibrated to
  the sensitivity of the output and a target (ε, δ) budget
- **Confidence suppressor** — caps and bins prediction confidence to
  reduce the precision of information leaked through confidence scores;
  supports configurable suppression levels (coarse/medium/fine)
- **k-anonymity response checker** — verifies that a prediction
  response cannot uniquely identify a record; checks whether the
  predicted class is shared by at least k training records with
  similar feature patterns

---

## File Structure

```
privacy-preserving-inference/
├── README.md
├── requirements.txt
├── output_perturbation.py      # Calibrated noise addition to model outputs
├── confidence_suppressor.py    # Confidence capping and binning
├── kanonymity_checker.py       # k-anonymity response verification
└── tests/
    └── test_inference_privacy.py
```
