# Privacy Budget Register
## AI Fortress — Chapter 13 Template 13.F-2

**Purpose:** Track (ε, δ)-differential privacy budget allocation and consumption
across all ML training runs and data release operations.  
**Owner:** Privacy Engineering / ML Platform Team  
**Review cadence:** Weekly during active training; monthly otherwise.

---

## Budget Allocation Table

One row per model or data release operation. Update `Spent` column after each training run.

| Model / Operation | Version | ε Budget | δ Budget | ε Spent | % Consumed | Status | Last Updated | Owner |
|-------------------|---------|---------|---------|---------|-----------|--------|-------------|-------|
| | | | 1e-5 | | | ☐ Active ☐ Exhausted ☐ Paused | | |
| | | | 1e-5 | | | ☐ Active ☐ Exhausted ☐ Paused | | |
| | | | 1e-5 | | | ☐ Active ☐ Exhausted ☐ Paused | | |

---

## Parameter Reference

### Recommended (ε, δ) Settings by Context

| Context | Recommended ε | Recommended δ | Notes |
|---------|--------------|--------------|-------|
| Healthcare / medical data | 0.1 – 1.0 | 1/N² | Strong privacy; HIPAA context |
| Financial / credit data | 1.0 – 4.0 | 1/N² | EU AI Act high-risk context |
| HR / employment data | 1.0 – 4.0 | 1/N² | High-risk AI Act category |
| Consumer behaviour | 2.0 – 8.0 | 1/N | Moderate risk |
| Aggregate / public data | 8.0 – 10.0 | 1/N | Low re-identification risk |
| Research / publication | ≤ 1.0 | 1/N² | Publication-quality DP |
| Federated learning | 4.0 – 10.0 | 1/N | Per global model |

> **Rule of thumb:** δ < 1/N where N = dataset size.
> δ = 1/N² is stronger and preferred for sensitive data.

### Noise Multiplier Quick Reference (Gaussian Mechanism)

| ε | δ | N | Recommended σ (noise_multiplier) |
|---|---|---|----------------------------------|
| 1.0 | 1e-5 | 10,000 | ≈ 3.5 |
| 2.0 | 1e-5 | 10,000 | ≈ 1.75 |
| 4.0 | 1e-5 | 10,000 | ≈ 0.875 |
| 8.0 | 1e-5 | 10,000 | ≈ 0.44 |
| 1.0 | 1e-5 | 100,000 | ≈ 4.4 |
| 4.0 | 1e-5 | 100,000 | ≈ 1.1 |

---

## Budget Spending Log

Append one row for each training epoch or data release that consumes budget.

| Date | Model / Op | Version | Run ID | ε Increment | ε Cumulative | δ | Steps / Epochs | Noise σ | Clip C | Approved By |
|------|-----------|---------|--------|------------|-------------|---|----------------|---------|-------|-------------|
| | | | | | | | | | | |
| | | | | | | | | | | |

---

## Budget Exhaustion Protocol

When any model reaches **80% of ε budget**, the following actions are triggered:

1. ☐ Alert sent to model owner and privacy engineer
2. ☐ No new training runs approved without explicit sign-off
3. ☐ Options evaluated: (a) request new dataset, (b) reduce epochs, (c) increase σ

When **100% is reached**:

1. ☐ Training immediately halted
2. ☐ Model locked to current checkpoint
3. ☐ Privacy budget exhaustion logged in audit trail
4. ☐ DPO notified if model is in production

---

## Composition Notes

When the same dataset is used for multiple purposes (model training + synthetic data
release + statistics publication), **composition applies**:

| Operation 1 | ε₁ | Operation 2 | ε₂ | Total (sequential) | Total (advanced) |
|-------------|---|-------------|---|-------------------|-----------------|
| Training | | Statistics | | ε₁ + ε₂ | √(2 ln(1/δ)(ε₁² + ε₂²)) |
| Training | | Synthetic release | | ε₁ + ε₂ | *(use accountant)* |

> Use the **RDP accountant** (resource 13.A `privacy_accountant.py`) for tight
> composition bounds across many operations.

---

## Sign-off Log

| Date | Review Type | Reviewer | Findings | Action |
|------|-------------|---------|----------|--------|
| | Monthly review | | | |
| | Incident review | | | |

---

*Template: AI Fortress Chapter 13 · Mohan Krishnamurthy*
