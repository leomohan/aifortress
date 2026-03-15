# Ch.12-A — Secure Model Versioning Pipeline

**AI Fortress** · Chapter 12: Model Versioning, Governance & Rollback Integrity

---

## What This Does

Implements a secure, auditable model versioning pipeline:

- **Semantic version registry** — enforces SemVer (MAJOR.MINOR.PATCH)
  discipline on model versions; validates version strings; prevents
  downgrade registrations; tracks version history per model name;
  supports pre-release tags (e.g. `2.1.0-rc.1`)
- **Artefact signer** — computes SHA-256 content digest of model
  artefact bytes; signs the digest with HMAC-SHA256 using a
  configurable signing key; produces a `SignedArtefact` record
  containing the digest, signature, algorithm, signer identity, and
  timestamp; `verify()` confirms digest and signature integrity
- **Content-addressable store** — stores model artefact metadata
  keyed by SHA-256 content hash; prevents duplicate storage of
  identical artefacts; provides lookup by hash and by
  (model_name, version) coordinates; detects hash mismatches on
  retrieval (tamper detection)
- **Promotion gate** — enforces an approval workflow before a model
  version can advance through stages (`dev → staging → production`);
  each stage transition requires a gate decision; gates can be
  auto-approved (CI) or require named approver sign-off; blocked
  transitions are logged with reason
- **Version lineage graph** — records parent→child relationships
  between model versions (fine-tune chains, distillation, ensemble
  inputs); resolves full ancestry and descendant trees; detects
  cycles; exports lineage as adjacency list

---

## File Structure

```
model-versioning-pipeline/
├── README.md
├── requirements.txt
├── version_registry.py         # SemVer enforcement and version history
├── artefact_signer.py          # HMAC-SHA256 artefact signing and verification
├── content_addressable_store.py # SHA-256 content-addressed artefact store
├── promotion_gate.py           # Stage promotion approval workflow
├── version_lineage.py          # Model version lineage DAG
└── tests/
    └── test_versioning.py
```
