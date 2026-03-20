# AI Fortress — Chapter 14 Code Resources
## Compliance, Governance & Audit Evidence

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle
**Author:** Mohan Krishnamurthy
**Chapter:** 14 of 17

---

## Resources in This Package

| ID | Folder | Type | Description |
|----|--------|------|-------------|
| 14.A | `evidence-collection/` | Code | Automated audit evidence collector: artefact harvester, evidence package builder, chain-of-custody logger |
| 14.B | `maturity-assessment/` | Code | AI security maturity assessment: domain scorer, gap analyser, roadmap generator |
| 14.C | `governance-policy-templates/` | Templates | Risk register, regulatory mapping matrix, and governance policy framework |

---

## Quick Setup

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Compliance Framework Coverage (Chapter 14)

| Framework | Scope | Key Controls |
|-----------|-------|-------------|
| EU AI Act | High-risk AI systems | Art.9 risk mgmt, Art.10 data, Art.11 docs, Art.12 logging, Art.13 transparency |
| NIST AI RMF | All AI systems | GOVERN, MAP, MEASURE, MANAGE functions |
| ISO/IEC 42001 | AI management systems | Clauses 4-10 |
| NIST CSF 2.0 | Cybersecurity | IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER |
| SOC 2 Type II | Service organisations | Security, Availability, Confidentiality |
| ISO/IEC 27001 | Information security | Annex A controls |
| GDPR | Personal data processing | Art.5, 25, 32, 35, 83 |

---

## Maturity Levels

| Level | Label | Description |
|-------|-------|-------------|
| 0 | None | No controls in place |
| 1 | Initial | Ad hoc, undocumented |
| 2 | Developing | Partially documented, inconsistently applied |
| 3 | Defined | Documented, consistently applied |
| 4 | Managed | Measured, monitored, and reported |
| 5 | Optimising | Continuously improved, industry-leading |

---

## Companion Site

**https://[your-domain]/resources/ch14**

---

*AI Fortress. Mohan Krishnamurthy. For educational and professional use.*
