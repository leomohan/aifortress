# Data Protection Impact Assessment (DPIA) Worksheet
## AI Fortress — Chapter 13 Template 13.F-1

**Version:** 1.0  
**Standard:** GDPR Article 35 / ISO 29134  
**Instructions:** Complete all sections before deploying any high-risk AI system.
A system is high-risk if it: processes special category data, makes automated decisions
with significant effects, involves large-scale profiling, or is listed in EU AI Act Annex III.

---

## Section 1: Project Information

| Field | Value |
|-------|-------|
| **Project / System Name** | |
| **Version / Release** | |
| **Data Controller** | |
| **Data Protection Officer (DPO)** | |
| **Project Owner** | |
| **Assessment Date** | |
| **Review Date** | |
| **Assessment Status** | ☐ Draft  ☐ Under Review  ☐ Approved  ☐ Conditionally Approved  ☐ Rejected |

---

## Section 2: Processing Description

### 2.1 Purpose and Legal Basis

| Field | Detail |
|-------|--------|
| **Primary purpose of processing** | |
| **Secondary purposes (if any)** | |
| **GDPR legal basis** | ☐ Consent (Art.6(1)(a)) ☐ Contract (Art.6(1)(b)) ☐ Legal obligation (Art.6(1)(c)) ☐ Vital interests (Art.6(1)(d)) ☐ Public task (Art.6(1)(e)) ☐ Legitimate interests (Art.6(1)(f)) |
| **Special category basis (if applicable)** | ☐ Explicit consent (Art.9(2)(a)) ☐ Employment law (Art.9(2)(b)) ☐ Research (Art.9(2)(j)) ☐ Other: |
| **Automated decision-making (Art.22)?** | ☐ Yes — solely automated with significant effects ☐ Yes — with human review ☐ No |

### 2.2 Data Categories

| Data Category | Special Category? | Volume (approx) | Retention Period |
|---------------|------------------|-----------------|-----------------|
| | ☐ Yes ☐ No | | |
| | ☐ Yes ☐ No | | |
| | ☐ Yes ☐ No | | |

### 2.3 Data Subjects

| Group | Estimated Numbers | Relationship to Controller | Vulnerable? |
|-------|-----------------|--------------------------|-------------|
| | | | ☐ Yes ☐ No |
| | | | ☐ Yes ☐ No |

### 2.4 Third-Party Recipients and Transfers

| Recipient | Purpose | Legal Basis | Location | Safeguards |
|-----------|---------|-------------|----------|------------|
| | | | | |

---

## Section 3: AI System Characteristics

| Field | Value |
|-------|-------|
| **Model type / algorithm** | |
| **Training data sources** | |
| **Inference environment** | ☐ Cloud ☐ On-premise ☐ Edge ☐ Hybrid |
| **EU AI Act risk tier** | ☐ Unacceptable ☐ High ☐ Limited ☐ Minimal |
| **Output type** | ☐ Classification ☐ Score/Ranking ☐ Generation ☐ Recommendation ☐ Other: |
| **Human oversight mechanism** | |
| **Explainability method** | |
| **Bias evaluation completed?** | ☐ Yes (attach report) ☐ No — justify: |

---

## Section 4: Necessity and Proportionality

Answer each question. A "No" answer requires a documented justification or mitigation.

| Question | Answer | Justification / Mitigation |
|----------|--------|---------------------------|
| Is the processing necessary for the stated purpose? | ☐ Yes ☐ No | |
| Could a less intrusive method achieve the same purpose? | ☐ Yes ☐ No | |
| Is the data volume proportionate? | ☐ Yes ☐ No | |
| Is the retention period as short as possible? | ☐ Yes ☐ No | |
| Are data subjects informed (transparency)? | ☐ Yes ☐ No | |
| Do data subjects have rights (access, erasure, portability)? | ☐ Yes ☐ No | |
| Has data minimisation been applied? | ☐ Yes ☐ No | |

---

## Section 5: Privacy Risk Assessment

### 5.1 Risk Identification

For each risk, rate likelihood (1–5) and impact (1–5). Risk score = likelihood × impact.

| Risk | Likelihood (1–5) | Impact (1–5) | Score | Existing Controls | Residual Risk |
|------|-----------------|-------------|-------|------------------|--------------|
| Unauthorised access to training data | | | | | |
| Membership inference attack | | | | | |
| Attribute inference from model outputs | | | | | |
| Re-identification of pseudonymised data | | | | | |
| Discriminatory / biased model decisions | | | | | |
| Data breach during model transfer | | | | | |
| Unlawful cross-border transfer | | | | | |
| Failure of data subject rights mechanisms | | | | | |
| Model inversion / data reconstruction | | | | | |
| *(Add rows as needed)* | | | | | |

### 5.2 Risk Scoring Key

| Score Range | Level | Action Required |
|-------------|-------|----------------|
| 1–4 | Low | Document; no immediate action |
| 5–9 | Medium | Implement additional controls |
| 10–16 | High | Mandatory mitigation before deployment |
| 17–25 | Critical | Consult DPA; may prohibit processing |

---

## Section 6: Measures to Address Risk

| Risk (from §5) | Measure | Owner | Target Date | Status |
|----------------|---------|-------|-------------|--------|
| | | | | ☐ Planned ☐ In Progress ☐ Implemented |
| | | | | ☐ Planned ☐ In Progress ☐ Implemented |

---

## Section 7: DPO Opinion

| Field | Value |
|-------|-------|
| **DPO recommendation** | ☐ Approved ☐ Conditionally Approved ☐ Rejected |
| **Conditions (if any)** | |
| **DPA consultation required?** | ☐ Yes — Art.36 consultation required ☐ No |
| **DPO signature** | |
| **Date** | |

---

## Section 8: Sign-off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Project Owner | | | |
| Data Controller | | | |
| DPO | | | |
| Information Security | | | |
| Legal / Compliance | | | |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | | | Initial draft |

---

*Template: AI Fortress Chapter 13 · Mohan Krishnamurthy*  
*For educational and professional use. Consult qualified legal counsel before deployment.*
