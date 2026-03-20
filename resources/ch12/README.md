# AI Fortress — Chapter 12 Code Resources
## Model Versioning, Governance & Rollback Integrity

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 12 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 12.A | `model-versioning-pipeline/` | Secure model versioning: semantic versioning enforcement, cryptographic artefact signing, content-addressable storage with SHA-256, promotion gates with approval workflow, and version lineage graph |
| 12.B | `model-card-generator/` | Automated model card generation: structured metadata extraction, risk and bias documentation, intended use and limitations, evaluation results formatter, and machine-readable model card schema |
| 12.C | `rollback-integrity/` | Safe model rollback: rollback eligibility checker, atomic swap with health validation, rollback audit trail, and blast-radius estimator for downstream service impact |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 12)

1. Unsigned model artefacts enabling silent substitution attacks
2. Version confusion from missing semantic versioning discipline
3. Uncontrolled promotions bypassing approval gates to production
4. Model card omissions hiding known bias or safety limitations
5. Rollback to a known-vulnerable version without integrity verification
6. Rollback blast radius — unknown downstream service dependencies
7. Lineage gaps enabling training data provenance disputes
8. Metadata tampering in model registry records

---

## Companion Site

**https://[your-domain]/resources/ch12**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
