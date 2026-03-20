# Ch.03-B — Label Validation Pipeline

**AI Fortress** · Chapter 3: Data Quality & Contamination

---

## What This Does

Multi-method label auditing pipeline for ML training datasets:

- **Inter-annotator agreement (IAA)** — Cohen's Kappa, Fleiss' Kappa, and Krippendorff's Alpha for multi-annotator datasets; flags labels with systematic annotator disagreement
- **Confidence-based label cleaning** — trains a fast cross-validation classifier and flags samples whose predicted probability diverges strongly from the assigned label (cleanlab-style noise detection)
- **Noise-rate estimator** — estimates the fraction of mislabelled samples per class using the confident learning framework (Northcutt et al. 2021)
- **Golden-set validator** — compares labels against a trusted golden reference set; measures precision, recall, and per-class error rates; generates a calibrated trust score per annotator
- **Label audit report** — structured JSON + Markdown report of all findings with per-class noise estimates and recommended re-annotation priorities

---

## File Structure

```
label-validation-pipeline/
├── README.md
├── requirements.txt
├── iaa_calculator.py          # Inter-annotator agreement (Cohen/Fleiss/Krippendorff)
├── confidence_cleaner.py      # Cross-val confidence-based mislabel detection
├── noise_rate_estimator.py    # Confident learning noise-rate estimation
├── golden_set_validator.py    # Golden-set comparison and annotator trust scoring
├── label_audit_report.py      # Audit report generator
└── tests/
    └── test_label_validation.py
```

## Quick Start

```python
from iaa_calculator import IAACalculator
from confidence_cleaner import ConfidenceCleaner
from golden_set_validator import GoldenSetValidator

# Inter-annotator agreement
iaa = IAACalculator()
result = iaa.cohens_kappa(labels_a=df["ann1"], labels_b=df["ann2"])
print(f"Cohen's κ = {result.kappa:.3f}  ({result.interpretation})")

# Confidence-based cleaning
cleaner = ConfidenceCleaner()
noisy_indices = cleaner.find_noisy_labels(X=features, y=labels)
print(f"Suspected mislabelled: {len(noisy_indices)} samples")

# Golden-set validation
validator = GoldenSetValidator()
report = validator.validate(predicted=df["label"], golden=golden_df["true_label"])
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
