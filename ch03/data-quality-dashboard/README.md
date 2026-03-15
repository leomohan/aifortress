# Ch.03-C — Data Quality Dashboard

**AI Fortress** · Chapter 3: Data Quality & Contamination

---

## What This Does

Automated data quality scoring framework for ML pipelines. Monitors data
across four quality dimensions at every pipeline stage:

- **Schema validator** — enforces column presence, dtype constraints, value ranges, and cardinality bounds; produces structured violation reports with severity levels
- **Completeness checker** — measures missing-value rates per column and per-row; applies configurable thresholds and flags columns that exceed missingness budgets
- **Consistency checker** — detects cross-column constraint violations (e.g. `end_date > start_date`), referential integrity violations, and duplicate primary keys
- **Quality scorer** — aggregates completeness, consistency, schema, and statistical checks into a single 0–100 quality score per dataset with a pass/fail gate
- **Pipeline stage monitor** — compares quality scores across pipeline stages (raw → cleaned → featured → split) to detect regressions introduced by preprocessing

---

## File Structure

```
data-quality-dashboard/
├── README.md
├── requirements.txt
├── schema_validator.py        # Schema enforcement and violation reporting
├── completeness_checker.py    # Missing-value analysis
├── consistency_checker.py     # Cross-column and referential integrity checks
├── quality_scorer.py          # Composite quality score aggregator
├── pipeline_monitor.py        # Stage-to-stage quality regression detection
└── tests/
    └── test_data_quality.py
```

## Quick Start

```python
from schema_validator import SchemaValidator, ColumnSpec
from quality_scorer import QualityScorer

schema = SchemaValidator([
    ColumnSpec("age",   dtype="numeric", min_val=0,  max_val=120, nullable=False),
    ColumnSpec("email", dtype="string",  nullable=False),
    ColumnSpec("label", dtype="categorical", allowed_values=["cat","dog"]),
])
violations = schema.validate(df)

scorer = QualityScorer()
score  = scorer.score(df, schema_violations=violations)
print(f"Quality score: {score.score}/100 — {'PASS' if score.passed else 'FAIL'}")
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
