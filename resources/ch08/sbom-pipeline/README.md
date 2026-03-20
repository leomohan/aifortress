# Ch.08-A — SBOM Pipeline

**AI Fortress** · Chapter 8: Software Supply Chain Security for ML

---

## What This Does

Generates, validates, and diffs Software Bills of Materials for ML projects:

- **SBOM generator** — introspects the active Python environment (or a
  `requirements.txt` / `pip freeze` snapshot) and produces a CycloneDX 1.4
  JSON SBOM with component name, version, PURL, licence, and hash for every
  installed package; optionally includes model artefacts as additional components
- **Model card SBOM extension** — extends the base SBOM with ML-specific
  metadata: training dataset provenance, base model lineage, fine-tuning
  framework and version, and evaluation benchmark references; produces a
  CycloneDX `externalReferences` section linking to model cards
- **SBOM differ** — compares two SBOM snapshots and reports: added components
  (new packages), removed components, version changes, and licence changes;
  raises an alert if any change introduces a package not on the approved list

---

## File Structure

```
sbom-pipeline/
├── README.md
├── requirements.txt
├── sbom_generator.py           # CycloneDX SBOM generation from pip environment
├── model_card_extension.py     # ML metadata SBOM extension
├── sbom_differ.py              # SBOM snapshot comparison and drift detection
└── tests/
    └── test_sbom_pipeline.py
```

## Quick Start

```python
from sbom_generator import SBOMGenerator

gen  = SBOMGenerator(project_name="fraud-detector", version="1.0.0")
sbom = gen.from_requirements_txt("requirements.txt")
gen.save(sbom, "sbom.json")
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
