# Ch.04-C — Model and ML System Report (MMSR) Generator

**AI Fortress** · Chapter 4: Secure Training Environment

---

## What This Does

Generates a structured Model and ML System Report (MMSR) — the security
and governance equivalent of a model card, capturing the evidence that
a training run was conducted securely and reproducibly:

- **Training configuration collector** — records hyperparameters, framework
  versions, hardware spec, batch sizes, and optimiser config in a structured
  schema; detects and flags missing security-relevant fields
- **Compute provenance tracker** — records where training ran (cloud region,
  instance type, account), when, for how long, and whether isolated network
  policies and GPU hygiene were applied
- **Data lineage recorder** — captures the dataset IDs, version hashes,
  preprocessing pipeline steps, and split ratios that produced the training,
  validation, and test sets
- **Security controls evidence** — records which Chapter 4 controls were active
  during training (secrets manager, workspace isolation, anomaly detection,
  checkpoint integrity) and links to their audit artefacts
- **MMSR report generator** — assembles all evidence into a signed JSON + Markdown
  MMSR document suitable for model governance review boards and regulatory audit

---

## File Structure

```
mmsr-generator/
├── README.md
├── requirements.txt
├── training_config.py         # Training configuration schema and collector
├── compute_provenance.py      # Compute environment and isolation evidence
├── data_lineage.py            # Dataset version, pipeline, and split recorder
├── security_controls.py       # Security control attestation registry
├── mmsr_report.py             # MMSR assembler and signed report generator
└── tests/
    └── test_mmsr.py
```

## Quick Start

```python
from training_config import TrainingConfig
from compute_provenance import ComputeProvenance
from data_lineage import DataLineage
from security_controls import SecurityControlsEvidence
from mmsr_report import MMSRReport

config    = TrainingConfig(model_name="fraud-detector-v3", ...)
provenance = ComputeProvenance.capture()
lineage   = DataLineage(dataset_id="customers-v3", ...)
controls  = SecurityControlsEvidence(job_id="train-001")
controls.attest("secrets_manager",        active=True, evidence_ref="sm-log-001")
controls.attest("workspace_isolation",    active=True, evidence_ref="ws-cert-001")
controls.attest("checkpoint_integrity",   active=True, evidence_ref="manifest.json")

mmsr = MMSRReport.build(config, provenance, lineage, controls)
mmsr.save_markdown("mmsr_fraud_detector_v3.md")
mmsr.save_json("mmsr_fraud_detector_v3.json")
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
