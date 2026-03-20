# Regulatory and Framework Mapping Matrix
## AI Fortress — Chapter 14 Template 14.C-2

**Organisation:** ___________________________________  
**Systems in Scope:** ___________________________________  
**Matrix Owner:** ___________________________________  
**Version:** 1.0  
**Last Updated:** ___________________________________

---

## Purpose

This matrix maps the AI security and governance controls documented in AI Fortress across applicable regulatory requirements and industry frameworks. It enables:

- **Audit readiness** — identify which evidence satisfies which control
- **Gap analysis** — spot controls not yet implemented
- **Cross-framework efficiency** — understand which single control satisfies multiple requirements
- **Regulatory change management** — assess impact of new regulations on existing control set

---

## Frameworks in Scope

| Code | Framework | Version | Applicability |
|------|-----------|---------|--------------|
| **EU-AI** | EU AI Act | 2024/1689 | High-risk AI systems operating in EU |
| **NIST-AI** | NIST AI Risk Management Framework | 1.0 (2023) | All AI systems |
| **ISO42** | ISO/IEC 42001 AI Management System | 2023 | All AI systems |
| **GDPR** | EU General Data Protection Regulation | 2016/679 | AI processing personal data of EU residents |
| **NIST-CF** | NIST Cybersecurity Framework | 2.0 (2024) | All systems |
| **ISO27** | ISO/IEC 27001 | 2022 | Information security management |
| **SOC2** | SOC 2 Type II | AICPA TSP | Service organisations |

Add / remove rows to reflect your organisation's applicable frameworks.

---

## Compliance Status Key

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully implemented and evidenced |
| 🔶 | Partially implemented — gaps exist |
| ❌ | Not implemented |
| N/A | Not applicable to this system |

---

## Part 1: Data Governance & Privacy Controls (Pillar 2 / Chapter 2)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Data provenance and lineage tracking | Ch.2 | Art.10(2) | MAP 1.1 | §8.4 | Art.5(1)(f) | ID.AM-3 | A.8.10 | Availability | | |
| Training data bias assessment | Ch.2, Ch.16 | Art.10(2)(f) | MEASURE 2.5 | §6.1.2 | Art.25 | — | — | — | | |
| Data minimisation and purpose limitation | Ch.2 | Art.10(3) | MAP 1.6 | §8.4 | Art.5(1)(b)(c) | PR.DS-5 | A.8.2 | Confidentiality | | |
| Personal data anonymisation pipeline | Ch.2 | Art.10(5) | — | — | Art.4, Rec.26 | PR.DS-1 | A.8.11 | Confidentiality | | |
| GDPR data governance compliance | Ch.2 | Art.10 | MAP 1.6 | §8.4 | Art.5,13,14 | — | A.5.34 | — | | |
| Compliance audit toolkit | Ch.2 | Art.17 | GOVERN 1.7 | §9.2 | Art.5(2) | — | A.5.35 | Security | | |

---

## Part 2: Data Quality & Contamination Controls (Pillar 3 / Chapter 3)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Contamination / poisoning detection | Ch.3 | Art.10(2)(e) | MEASURE 2.6 | §8.4 | — | DE.CM-4 | A.8.8 | — | | |
| Label validation pipeline | Ch.3 | Art.10(2)(d) | MAP 1.5 | §8.4 | — | — | — | — | | |
| Data quality dashboard | Ch.3 | Art.10(2) | MEASURE 2.5 | §9.1 | Art.5(1)(d) | ID.AM-3 | — | Availability | | |

---

## Part 3: Secure Training Controls (Pillar 4 / Chapter 4)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Secure training environment | Ch.4 | Art.15(1) | MANAGE 4.1 | §8.5 | Art.32 | PR.AC-3 | A.8.21 | Security | | |
| Training anomaly detection | Ch.4 | Art.9(7) | MEASURE 2.6 | §8.5 | — | DE.CM-1 | A.8.16 | — | | |
| Model security report (MMSR) | Ch.4 | Art.11 | GOVERN 1.2 | §7.5 | — | ID.RA-1 | A.5.7 | — | | |

---

## Part 4: Inference Security Controls (Pillar 5 / Chapter 5)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| API hardening | Ch.5 | Art.15(3) | MANAGE 4.1 | §8.7 | Art.32 | PR.AC-5 | A.8.21 | Security | | |
| Adversarial defence | Ch.5 | Art.15(1) | MEASURE 2.6 | §8.7 | — | PR.IP-12 | A.8.8 | — | | |
| Prompt injection classifier | Ch.5 | Art.15(1) | MANAGE 4.2 | §8.7 | — | DE.CM-4 | A.8.8 | — | | |

---

## Part 5: Model IP & Integrity Controls (Pillar 6 / Chapter 6)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Model encryption and signing | Ch.6 | Art.15(2) | MANAGE 4.1 | §8.5 | — | PR.DS-1 | A.8.24 | Confidentiality | | |
| Watermarking pipeline | Ch.6 | Art.16(g) | GOVERN 1.1 | §8.5 | — | PR.IP-3 | A.5.32 | — | | |
| IP protection toolkit | Ch.6 | Art.16 | GOVERN 1.1 | §8.5 | — | PR.DS-1 | A.5.32 | Confidentiality | | |

---

## Part 6: Infrastructure Security Controls (Pillar 7 / Chapter 7)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| IaC security hardening | Ch.7 | Art.17 | MANAGE 4.1 | §8.7 | Art.32 | PR.AC-4 | A.8.9 | Security | | |
| Storage hardening | Ch.7 | Art.10(1) | MANAGE 4.1 | §8.7 | Art.32 | PR.DS-1 | A.8.10 | Confidentiality | | |
| Disaster recovery | Ch.7 | Art.15(3) | MANAGE 4.5 | §8.7 | Art.32(1)(c) | RC.RP-1 | A.8.13 | Availability | | |

---

## Part 7: Supply Chain Security Controls (Pillar 8 / Chapter 8)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| SBOM pipeline | Ch.8 | Art.13(3)(b) | MAP 1.2 | §8.4 | — | ID.SC-2 | A.5.21 | — | | |
| Dependency scanning | Ch.8 | Art.17 | MAP 1.2 | §8.4 | — | ID.SC-4 | A.8.8 | Security | | |
| Pre-trained model assessment | Ch.8 | Art.10(2)(e) | MAP 1.2 | §8.4 | — | ID.SC-2 | A.5.21 | — | | |
| CI/CD hardening (SLSA) | Ch.8 | Art.17 | MANAGE 4.1 | §8.5 | — | PR.IP-3 | A.8.27 | Security | | |

---

## Part 8: Network Security Controls (Pillar 9 / Chapter 9)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| API gateway security | Ch.9 | Art.15(3) | MANAGE 4.1 | §8.7 | Art.32 | PR.AC-5 | A.8.21 | Security | | |
| Service mesh / zero trust | Ch.9 | Art.15(3) | MANAGE 4.1 | §8.7 | Art.32 | PR.AC-3 | A.8.22 | Security | | |
| Secrets rotation | Ch.9 | Art.17 | MANAGE 4.1 | §8.7 | Art.32 | PR.AC-1 | A.8.24 | Security | | |

---

## Part 9: Monitoring & Detection Controls (Pillar 10 / Chapter 10)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Drift detection dashboard | Ch.10 | Art.72 | MEASURE 2.5 | §9.1 | — | DE.AE-1 | A.8.16 | Availability | | |
| SOC integration | Ch.10 | Art.72 | MEASURE 2.7 | §9.1 | — | DE.CM-1 | A.8.16 | Security | | |
| Monitoring stack | Ch.10 | Art.9(7), Art.72 | MEASURE 2.5 | §9.1 | — | DE.CM-3 | A.8.15 | Availability | | |

---

## Part 10: Access & Identity Controls (Pillar 11 / Chapter 11)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| IAM access control | Ch.11 | Art.17 | MANAGE 4.1 | §8.7 | Art.32 | PR.AC-1 | A.5.15 | Security | | |
| PAM integration | Ch.11 | Art.17 | MANAGE 4.1 | §8.7 | Art.32 | PR.AC-4 | A.5.18 | Security | | |
| Access review automation | Ch.11 | Art.17 | GOVERN 1.4 | §9.2 | Art.32 | PR.AC-1 | A.5.18 | Security | | |

---

## Part 11: Model Versioning & Governance Controls (Pillar 12 / Chapter 12)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Model versioning pipeline | Ch.12 | Art.11, Art.72 | MANAGE 4.3 | §8.5 | — | PR.IP-3 | A.8.32 | Security | | |
| Model card generator | Ch.12 | Art.13 | GOVERN 1.2 | §7.5 | Art.13,14 | — | — | — | | |
| Rollback and integrity | Ch.12 | Art.15(2) | MANAGE 4.3 | §8.5 | — | RC.RP-1 | A.8.32 | Availability | | |

---

## Part 12: Privacy-Preserving ML Controls (Pillar 13 / Chapter 13)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Differential privacy (DP-SGD) | Ch.13 | Art.10(5) | MAP 1.6 | §8.4 | Art.25, Art.32 | PR.DS-1 | A.8.11 | Confidentiality | | |
| Federated learning with DP | Ch.13 | Art.10(5) | MAP 1.6 | §8.4 | Art.25 | PR.DS-5 | A.8.11 | Confidentiality | | |
| Privacy audit suite | Ch.13 | Art.9(9) | MEASURE 2.6 | §9.2 | Art.35 | — | A.5.34 | — | | |
| DPIA / privacy budget templates | Ch.13 | Art.9(9) | MAP 1.6 | §8.4 | Art.35 | — | A.5.34 | — | | |

---

## Part 13: Compliance & Audit Controls (Pillar 14 / Chapter 14)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Evidence collection system | Ch.14 | Art.17, Art.72 | GOVERN 1.7 | §9.2 | Art.5(2) | — | A.5.35 | Security | | |
| Maturity assessment | Ch.14 | Art.9 | GOVERN 1.7 | §9.1 | — | ID.RA-3 | A.5.35 | — | | |
| Risk register | Ch.14 | Art.9(2) | MAP 2.1 | §6.1.2 | Art.35 | ID.RA-6 | A.6.4 | — | | |
| Regulatory mapping matrix | Ch.14 | Art.9 | GOVERN 6 | §4.2 | — | ID.GV-1 | A.5.31 | — | | |

---

## Part 14: Edge & IoT Security Controls (Pillar 15 / Chapter 15)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Hardware root of trust integration | Ch.15 | Art.15(2) | MANAGE 4.1 | §8.7 | — | PR.DS-1 | A.8.21 | Security | | |
| Encrypted model (TrustZone) | Ch.15 | Art.15(2) | MANAGE 4.1 | §8.7 | — | PR.DS-1 | A.8.24 | Confidentiality | | |
| Secure OTA pipeline | Ch.15 | Art.15(2) | MANAGE 4.1 | §8.7 | — | PR.IP-3 | A.8.27 | Security | | |
| Physical adversarial evaluation | Ch.15 | Art.15(1) | MEASURE 2.6 | §8.7 | — | PR.IP-12 | A.8.8 | — | | |

---

## Part 15: Fairness & Explainability Controls (Pillar 16 / Chapter 16)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Fairness evaluation suite | Ch.16 | Art.10(2)(f) | MEASURE 2.5 | §8.4 | Art.22 | — | — | — | | |
| Bias mitigation | Ch.16 | Art.10(2)(f) | MANAGE 4.2 | §8.4 | Art.25 | — | — | — | | |
| AIA toolkit | Ch.16 | Art.9(2)(a) | MAP 2.3 | §6.1.2 | Art.35 | ID.RA-3 | — | — | | |
| Fairness monitoring | Ch.16 | Art.72 | MEASURE 2.5 | §9.1 | — | DE.AE-1 | — | — | | |
| Explainability / SHAP | Ch.16 | Art.13 | GOVERN 1.2 | §7.5 | Art.22 | — | — | — | | |

---

## Part 16: Incident Response Controls (Pillar 17 / Chapter 17)

| AI Fortress Control | Chapter | EU-AI | NIST-AI | ISO42 | GDPR | NIST-CF | ISO27 | SOC2 | Status | Evidence Reference |
|--------------------|---------|-------|---------|-------|------|---------|-------|------|--------|-------------------|
| Incident response toolkit | Ch.17 | Art.73 | RESPOND 1 | §10.2 | Art.33 | RS.RP-1 | A.5.26 | Security | | |
| Regulatory notification | Ch.17 | Art.73 | RESPOND 2 | §10.2 | Art.33,34 | RS.CO-2 | A.5.26 | — | | |
| Postmortem automation | Ch.17 | Art.72 | RESPOND 3 | §10.1 | — | RS.AN-5 | A.5.27 | — | | |
| Recovery playbooks | Ch.17 | Art.73 | RECOVER 1 | §10.2 | — | RC.RP-1 | A.5.29 | Availability | | |
| Tabletop exercises | Ch.17 | Art.9(7) | GOVERN 1.7 | §9.2 | — | RS.RP-1 | A.5.26 | Security | | |

---

## Coverage Summary

*Complete this section after populating status column above.*

| Framework | Total Controls Mapped | Implemented (✅) | Partial (🔶) | Not Implemented (❌) | Coverage % |
|-----------|----------------------|-----------------|------------|--------------------|-----------| 
| EU AI Act | | | | | |
| NIST AI RMF | | | | | |
| ISO 42001 | | | | | |
| GDPR | | | | | |
| NIST CSF 2.0 | | | | | |
| ISO 27001 | | | | | |
| SOC 2 | | | | | |

---

## Revision History

| Version | Date | Author | Summary |
|---------|------|--------|---------|
| 1.0 | | | Initial matrix |

---

*Template: AI Fortress Chapter 14 · Mohan Krishnamurthy*
