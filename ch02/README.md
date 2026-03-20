# AI Fortress — Chapter 2 Code Resources
## Data Privacy & Compliance

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 2 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 2.A | `gdpr-data-governance/` | GDPR/CCPA/HIPAA data governance: consent tracking, lawful-basis registry, DSR workflow, retention enforcement |
| 2.B | `anonymisation-pipeline/` | PII detection and anonymisation pipeline: k-anonymity, l-diversity, pseudonymisation, format-preserving tokenisation |
| 2.C | `compliance-audit-toolkit/` | Automated compliance audit: regulation-to-control mapping, evidence collector, gap report generator, DPIA templates |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

Each folder contains its own `README.md` with full usage instructions.

---

## Regulations Covered

- **GDPR** — Articles 5, 6, 9, 13–15, 17, 20, 25, 30, 35, 44–49
- **CCPA / CPRA** — Right to know, delete, opt-out, correct; sensitive PI handling
- **HIPAA** — Technical Safeguards (§164.312), Privacy Rule minimum necessary standard
- **EU AI Act** — Articles 10 (data governance), 13 (transparency), 71 (penalties)

---

## Companion Site

Full documentation and resources for all 17 chapters:  
**https://[your-domain]/resources/ch02**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
