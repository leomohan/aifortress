# Ch.10-A — ML Drift Detection Dashboard

**AI Fortress** · Chapter 10: Monitoring, Drift Detection & SOC Integration

---

## What This Does

Detects statistical drift in ML models and their input features in production:

- **Feature drift detector** — runs Kolmogorov-Smirnov (continuous) and
  chi-squared (categorical) tests per feature; computes Population Stability
  Index (PSI) for binned continuous features; flags features with drift
  above configurable thresholds; handles missing values and type mismatches
- **Prediction drift monitor** — tracks the output distribution of the model
  over time; detects shifts in predicted class probabilities or regression
  outputs using KS test and Jensen-Shannon divergence; alerts when prediction
  distribution departs from the baseline established at deployment
- **Feature importance drift** — compares SHAP-style feature importance
  rankings between baseline and current window; flags rank inversions and
  importance magnitude changes that may indicate adversarial feature
  manipulation or upstream data pipeline issues
- **Drift report** — aggregates all signals into a structured report with
  per-feature status, overall drift score, and a pass/fail gate; saves to
  JSON for downstream SIEM ingestion

---

## File Structure

```
drift-detection-dashboard/
├── README.md
├── requirements.txt
├── feature_drift_detector.py       # KS, chi-squared, PSI per feature
├── prediction_drift_monitor.py     # Output distribution shift detection
├── feature_importance_drift.py     # SHAP-rank inversion detection
├── drift_report.py                 # Aggregated drift report and gate
└── tests/
    └── test_drift_detection.py
```
