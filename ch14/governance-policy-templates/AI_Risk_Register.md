# AI Risk Register
## AI Fortress — Chapter 14 Template 14.C-1

**Organisation:** ___________________________________  
**System / Programme:** ___________________________________  
**Register Owner:** ___________________________________  
**Version:** 1.0  
**Last Updated:** ___________________________________  
**Review Frequency:** Quarterly or upon material change

---

## Purpose

This register records, scores, tracks, and reports all identified risks associated with AI systems across the ML lifecycle. It is a living document — risks are added as they are identified and updated as circumstances change.

**Scope:** Covers risks across the full ML lifecycle: data acquisition → training → evaluation → deployment → monitoring → decommission.

---

## Risk Scoring Methodology

**Risk Score = Likelihood × Impact**

| Score | Likelihood | Impact |
|-------|-----------|--------|
| 1 | Rare (< 5% per year) | Negligible — no material effect |
| 2 | Unlikely (5–20% per year) | Minor — limited, easily reversible |
| 3 | Possible (20–50% per year) | Moderate — significant but manageable |
| 4 | Likely (50–80% per year) | Major — significant harm or financial loss |
| 5 | Almost Certain (> 80% per year) | Catastrophic — existential, regulatory, or mass-harm |

| Risk Score | Rating | Response Required |
|-----------|--------|-----------------|
| 20–25 | **Critical** | Immediate escalation; treatment required before deployment/continuation |
| 12–19 | **High** | Senior management attention; treatment plan within 30 days |
| 6–11 | **Medium** | Management attention; treatment plan within 90 days |
| 1–5 | **Low** | Monitor; accept or treat in normal course |

---

## Risk Categories

| Code | Category | Description |
|------|----------|-------------|
| **DG** | Data Governance | Risks from data quality, bias, lineage, or regulatory non-compliance |
| **MI** | Model Integrity | Risks to model performance, robustness, or tamper resistance |
| **PR** | Privacy | Risks of personal data exposure or inference attack |
| **SC** | Supply Chain | Risks from third-party models, datasets, or dependencies |
| **OP** | Operational | Availability, performance, and infrastructure risks |
| **FA** | Fairness | Discriminatory outcomes or bias risks |
| **RG** | Regulatory | Compliance gaps with EU AI Act, GDPR, sector rules |
| **GV** | Governance | Accountability, oversight, or process gaps |

---

## Risk Register

> Instructions: Add one row per identified risk. Update Residual Score after controls are applied. Flag for escalation when Residual Score ≥ 12.

| Risk ID | Category | Risk Title | Risk Description | Inherent Likelihood | Inherent Impact | Inherent Score | Rating | Controls in Place | Residual Likelihood | Residual Impact | Residual Score | Residual Rating | Risk Owner | Treatment Plan | Target Date | Status | Last Reviewed |
|---------|----------|-----------|-----------------|--------------------|-----------------|--------------|----|-------------------|--------------------|-----------------|--------------|----|-----------|---------------|-------------|--------|--------------|
| R-001 | DG | Training data representation gap | Underrepresentation of minority groups in training data leading to biased model outputs | | | | | | | | | | | | | Open | |
| R-002 | MI | Adversarial input vulnerability | Model susceptible to adversarial examples causing misclassification | | | | | | | | | | | | | Open | |
| R-003 | PR | Model inversion attack | Adversary reconstructs training data from model queries | | | | | | | | | | | | | Open | |
| R-004 | SC | Compromised pre-trained model | Third-party foundation model contains backdoor or malicious weights | | | | | | | | | | | | | Open | |
| R-005 | OP | Model API availability | Model inference API experiences unplanned downtime affecting critical decisions | | | | | | | | | | | | | Open | |
| R-006 | FA | Disparate impact in production | Model produces discriminatory outcomes for protected groups in live deployment | | | | | | | | | | | | | Open | |
| R-007 | RG | EU AI Act Art.13 non-compliance | Insufficient transparency documentation for high-risk AI system | | | | | | | | | | | | | Open | |
| R-008 | GV | Insufficient human oversight | Automated decisions made without adequate human review for high-stakes outcomes | | | | | | | | | | | | | Open | |
| R-009 | DG | Data drift in production | Distribution of production inputs diverges from training data, degrading performance | | | | | | | | | | | | | Open | |
| R-010 | MI | Model weight exfiltration | Proprietary model weights stolen, enabling competitor reproduction or attack | | | | | | | | | | | | | Open | |
| *(add rows as needed)* | | | | | | | | | | | | | | | | | |

---

## Critical and High Risks Summary

*Auto-populate from register above. Update at each review cycle.*

| Risk ID | Title | Residual Score | Owner | Treatment Due | Status |
|---------|-------|---------------|-------|--------------|--------|
| | | | | | |

---

## Risk Treatment Options

| Option | Definition | When to Apply |
|--------|-----------|--------------|
| **Avoid** | Eliminate the risk by not undertaking the activity | Risk score Critical; no viable mitigation |
| **Reduce** | Apply controls to lower likelihood and/or impact | Most risks; preferred approach |
| **Transfer** | Shift risk to third party (insurance, contract) | Residual operational/financial risk |
| **Accept** | Acknowledge and monitor without treatment | Low risks below appetite threshold |

**Risk Appetite Statement:**  
The organisation accepts residual AI risk scores of 5 or below without escalation. Risks scoring 6–11 require documented treatment plans. Risks scoring 12 or above are not acceptable without explicit Board-level sign-off.

---

## Register Governance

| Role | Responsibility |
|------|---------------|
| **Risk Register Owner** | Maintains register currency; facilitates quarterly review |
| **CISO** | Approves treatment plans for High and Critical risks |
| **AI Ethics Lead** | Owns FA and GV category risks |
| **DPO** | Reviews PR and RG risks for GDPR/privacy implications |
| **ML Lead** | Owns MI, DG, and SC category risks |
| **Board / Risk Committee** | Receives quarterly summary; approves Critical risk acceptance |

---

## Revision History

| Version | Date | Author | Summary of Changes |
|---------|------|--------|-------------------|
| 1.0 | | | Initial register created |
| | | | |

---

*Template: AI Fortress Chapter 14 · Modo Bhaik*
