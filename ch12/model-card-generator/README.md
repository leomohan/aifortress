# Ch.12-B — Model Card Generator

**AI Fortress** · Chapter 12: Model Versioning, Governance & Rollback Integrity

---

## What This Does

Automates the generation of structured, machine-readable model cards:

- **Metadata extractor** — collects standardised model metadata:
  architecture, training framework, dataset references, training
  hyperparameters, compute used, and primary contact; validates
  that required fields are present before a card can be finalised
- **Risk and bias documenter** — structures known limitations,
  out-of-distribution failure modes, demographic bias findings,
  and regulatory risk classification; maps to EU AI Act risk tiers
  (minimal / limited / high / unacceptable)
- **Evaluation formatter** — formats evaluation results from
  multiple benchmark datasets into a consistent table structure;
  tracks per-slice performance (demographic, geographic, temporal
  slices); highlights performance gaps above a configurable threshold
- **Model card schema** — assembles all sections into a single
  `ModelCard` dataclass and serialises to JSON (machine-readable)
  and Markdown (human-readable); validates required sections
  before finalisation

---

## File Structure

```
model-card-generator/
├── README.md
├── requirements.txt
├── metadata_extractor.py       # Model metadata collection and validation
├── risk_bias_documenter.py     # Risk tier and bias findings documentation
├── evaluation_formatter.py     # Evaluation results table and slice analysis
├── model_card_schema.py        # Full model card assembly and serialisation
└── tests/
    └── test_model_cards.py
```
