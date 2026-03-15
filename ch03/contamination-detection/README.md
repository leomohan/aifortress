# Ch.03-A — Training Data Contamination Detection

**AI Fortress** · Chapter 3: Data Quality & Contamination

---

## What This Does

Statistical detection suite for the ten contamination threats defined in
Chapter 3's threat taxonomy. Operates on tabular, image-feature, and
NLP embedding datasets without requiring access to the original model:

- **Label-flip detector** — statistical tests on per-class label distributions;
  detects anomalous shifts in label ratios using chi-squared and Z-score analysis
- **Backdoor trigger detector** — identifies suspiciously uniform feature patterns
  across a subset of samples that predict a specific target class (trojan signature)
- **Distribution shift detector** — Maximum Mean Discrepancy (MMD) and
  Kolmogorov-Smirnov tests between a reference split and the current dataset
- **Duplicate / near-duplicate detector** — exact hash deduplication and
  MinHash LSH for near-duplicate detection at scale
- **Statistical outlier detector** — Isolation Forest and Z-score based
  outlier flagging with configurable contamination thresholds
- **Contamination report** — structured JSON report of all findings,
  per-threat severity, and recommended remediation actions

---

## File Structure

```
contamination-detection/
├── README.md
├── requirements.txt
├── label_flip_detector.py       # Chi-squared + Z-score label distribution tests
├── backdoor_detector.py         # Trigger pattern detection via feature clustering
├── distribution_shift.py        # MMD and KS-test shift detection
├── duplicate_detector.py        # Hash + MinHash LSH near-duplicate detection
├── outlier_detector.py          # Isolation Forest + Z-score outlier flagging
├── contamination_report.py      # Unified report aggregator
└── tests/
    └── test_contamination.py
```

## Quick Start

```python
import pandas as pd
from label_flip_detector import LabelFlipDetector
from distribution_shift import DistributionShiftDetector
from contamination_report import ContaminationReport

df = pd.read_parquet("train.parquet")

# Check for label flipping
lfd = LabelFlipDetector()
findings = lfd.detect(df, label_col="label", reference_ratios={"cat": 0.5, "dog": 0.5})

# Check for distribution shift vs reference split
dsd = DistributionShiftDetector()
shift = dsd.detect(reference_df=df_ref, current_df=df_new, feature_cols=["f1","f2","f3"])

# Aggregate into report
report = ContaminationReport(dataset_id="train-v3")
report.add_findings(findings)
report.add_findings(shift)
report.save("contamination_report.json")
print(report.summary())
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
