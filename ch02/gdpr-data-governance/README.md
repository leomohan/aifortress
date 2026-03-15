# Ch.02-A — GDPR / CCPA / HIPAA Data Governance

**AI Fortress** · Chapter 2: Data Privacy & Compliance

---

## What This Does

End-to-end data governance framework for ML training datasets covering the
three major privacy regulations applicable to ML systems:

- **Lawful-basis registry** — records the legal basis for each dataset (GDPR Art.6/9), with consent evidence, legitimate-interest assessments, and contractual necessity records
- **Consent management** — tracks consent grants and withdrawals per data subject per purpose; propagates withdrawals to downstream dataset references
- **Data Subject Request (DSR) workflow** — automates GDPR Art.15 (access), Art.17 (erasure), Art.20 (portability), and CCPA right-to-know/delete pipelines with 30-day SLA tracking
- **Records of Processing Activities (RoPA)** — GDPR Art.30 compliant RoPA generator; exports to JSON and CSV for DPA submission
- **Retention policy engine** — declares retention schedules per data category; flags and quarantines records past their retention date; generates deletion certificates
- **Cross-border transfer controls** — SCCs, BCRs, and adequacy-decision tracking for GDPR Chapter V; HIPAA BAA registry

---

## File Structure

```
gdpr-data-governance/
├── README.md
├── requirements.txt
├── lawful_basis.py          # Lawful-basis registry and consent tracker
├── dsr_workflow.py          # Data Subject Request pipeline (access/erase/port)
├── ropa.py                  # Records of Processing Activities generator
├── retention.py             # Retention policy engine and deletion certificate
├── transfer_controls.py     # Cross-border transfer and BAA registry
├── models.py                # Shared dataclasses (DataSet, DataSubject, etc.)
└── tests/
    └── test_governance.py
```

## Quick Start

```python
from lawful_basis import LawfulBasisRegistry, LegalBasis
from dsr_workflow import DSRWorkflow, DSRType
from ropa import RoPAGenerator

# Register a dataset's lawful basis
registry = LawfulBasisRegistry("governance.db")
registry.register(
    dataset_id   = "customers-v3",
    legal_basis  = LegalBasis.CONSENT,
    purpose      = "Training fraud-detection model",
    data_categories = ["name", "email", "transaction_history"],
    retention_days  = 730,
)

# Submit an erasure request (GDPR Art.17 / CCPA delete)
workflow = DSRWorkflow("governance.db")
request  = workflow.submit(
    subject_id = "user-abc123",
    dsr_type   = DSRType.ERASURE,
    regulation = "GDPR",
)
print(f"Request {request.request_id} — SLA: {request.sla_deadline}")

# Generate RoPA
ropa = RoPAGenerator("governance.db")
ropa.export_csv("ropa_export.csv")
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
