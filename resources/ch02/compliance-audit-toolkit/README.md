# Ch.02-C — Compliance Audit Toolkit

**AI Fortress** · Chapter 2: Data Privacy & Compliance

---

## What This Does

Automated compliance audit framework mapping regulations to controls,
collecting evidence, and generating gap-analysis reports:

- **Regulation control mapper** — maps GDPR, CCPA, HIPAA, and EU AI Act articles to specific technical and organisational controls; structured as a machine-readable registry
- **Evidence collector** — gathers audit artefacts (RoPA export, DPIA records, consent logs, DSR completion rates, encryption status, retention certificates) from the governance database
- **Gap analyser** — compares collected evidence against required controls per regulation; classifies each control as COMPLIANT, PARTIAL, or GAP
- **Report generator** — produces a structured compliance gap report in JSON and a human-readable Markdown summary, ready for DPO review or DPA submission
- **DPIA template** — pre-filled Data Protection Impact Assessment template for ML training datasets (GDPR Art.35)

---

## File Structure

```
compliance-audit-toolkit/
├── README.md
├── requirements.txt
├── control_registry.py       # Regulation → control mapping
├── evidence_collector.py     # Gathers evidence from governance DB
├── gap_analyser.py           # Compares evidence to required controls
├── report_generator.py       # JSON + Markdown report output
├── dpia_template.py          # GDPR Art.35 DPIA generator
└── tests/
    └── test_audit.py
```

## Quick Start

```python
from control_registry import ControlRegistry
from evidence_collector import EvidenceCollector
from gap_analyser import GapAnalyser
from report_generator import ReportGenerator

registry  = ControlRegistry()
collector = EvidenceCollector(governance_db="governance.db")
evidence  = collector.collect(dataset_id="customers-v3")
gaps      = GapAnalyser(registry).analyse(evidence, regulations=["GDPR","HIPAA"])
ReportGenerator().to_markdown(gaps, output_path="compliance_report.md")
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
