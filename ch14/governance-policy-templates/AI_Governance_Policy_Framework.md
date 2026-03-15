# AI Governance Policy Framework
## AI Fortress — Chapter 14 Template 14.C-3

**Organisation:** ___________________________________  
**Policy Owner:** ___________________________________  
**Approved By:** ___________________________________  
**Version:** 1.0  
**Effective Date:** ___________________________________  
**Next Review:** ___________________________________

---

## 1. Purpose and Scope

### 1.1 Purpose

This policy establishes the organisation's requirements for the responsible development, procurement, deployment, and decommissioning of AI systems. It defines accountability structures, mandatory controls, and governance processes to ensure AI systems are secure, fair, compliant, and trustworthy.

### 1.2 Scope

This policy applies to:

- All AI systems developed internally or procured from third parties
- All staff involved in commissioning, developing, operating, monitoring, or decommissioning AI systems
- All third-party vendors or contractors developing or operating AI systems on behalf of the organisation
- All deployment environments (cloud, on-premises, hybrid, edge)

### 1.3 Relationship to Other Policies

This policy is the overarching AI governance instrument. It is supported by:

| Policy / Standard | Relationship |
|------------------|-------------|
| Data Protection Policy | Governs personal data processing in AI systems |
| Information Security Policy | Governs technical security controls |
| Third-Party Risk Policy | Governs AI supply chain due diligence |
| Acceptable Use Policy | Governs employee use of AI tools |
| Incident Response Policy | Governs response to AI security incidents |

---

## 2. Definitions

| Term | Definition |
|------|-----------|
| **AI System** | A machine-based system that generates outputs such as predictions, recommendations, decisions, or content influencing real or virtual environments |
| **High-Risk AI System** | An AI system classified as high-risk under EU AI Act Annex III, or one that makes or materially influences decisions affecting individuals' significant interests |
| **General Purpose AI (GPAI)** | An AI model trained on large quantities of data that can perform a wide range of tasks (e.g. foundation models, LLMs) |
| **ML Lifecycle** | The end-to-end process from problem definition through data preparation, training, evaluation, deployment, monitoring, and decommission |
| **AI Incident** | An event where an AI system behaves unexpectedly, produces harmful outputs, is compromised, or causes harm to individuals or the organisation |
| **Senior Responsible Owner (SRO)** | The executive accountable for a specific AI system or programme |
| **AI Ethics Lead** | The designated person responsible for fairness, bias, and ethical oversight of AI systems |

---

## 3. Guiding Principles

All AI systems developed or operated by this organisation must adhere to the following principles:

| Principle | Requirement |
|-----------|------------|
| **Human oversight** | High-risk and high-impact AI decisions must have meaningful human review. Fully automated decisions with significant individual impact are prohibited without explicit legal basis. |
| **Fairness** | AI systems must not produce discriminatory outputs against individuals based on protected characteristics. Fairness metrics must be evaluated before deployment and monitored in production. |
| **Transparency** | Affected individuals have the right to know when an AI system has influenced a decision about them, and to receive a meaningful explanation. |
| **Accountability** | Every AI system must have a named Senior Responsible Owner and a documented accountability chain. |
| **Security by design** | Security controls must be embedded in AI systems from the outset, not added as an afterthought. |
| **Privacy by design** | AI systems processing personal data must apply data minimisation, purpose limitation, and privacy-enhancing technologies. |
| **Robustness** | AI systems must be designed to resist adversarial manipulation, perform reliably under distribution shift, and degrade gracefully. |
| **Proportionality** | Governance requirements are proportionate to risk. Higher-risk systems face more stringent controls. |

---

## 4. AI System Classification

### 4.1 Risk Tiers

All AI systems must be classified into one of four risk tiers before development or procurement:

| Tier | Label | Criteria | Examples |
|------|-------|----------|---------|
| **T1** | Critical | EU AI Act Annex III high-risk; or makes/influences decisions with legal or similarly significant effects on individuals | Credit scoring, recruitment screening, law enforcement analytics |
| **T2** | High | Not Annex III but affects >10,000 individuals/year; or handles sensitive personal data; or safety-relevant | Customer churn model, fraud detection, predictive maintenance |
| **T3** | Medium | Limited individual impact; reversible outputs; no sensitive personal data | Internal forecasting, content categorisation, search ranking |
| **T4** | Low | Fully automated, low stakes, no individual impact | Internal document summarisation, code assistance, spell-check |

### 4.2 Classification Process

- [ ] Business owner completes **AI System Registration Form** (Section 8.1)
- [ ] AI Ethics Lead and Legal review and confirm classification within 10 business days
- [ ] Classification is recorded in the **AI System Inventory**
- [ ] Classification is reviewed on any material change to purpose, data, or deployment context

---

## 5. Governance Requirements by Tier

### 5.1 Mandatory Requirements for All Tiers (T1–T4)

- [ ] AI System Registration (Section 8.1)
- [ ] Named Senior Responsible Owner
- [ ] Security risk assessment (Chapter 14 maturity-assessment tool)
- [ ] Documented data lineage
- [ ] Basic access controls (principle of least privilege)
- [ ] Incident reporting to AI Security team

### 5.2 Additional Requirements for T2 (High)

All T1 requirements plus:

- [ ] Fairness evaluation before deployment (resource 16.A)
- [ ] Model card (resource 12.B)
- [ ] Post-deployment monitoring plan (resource 16.D)
- [ ] Security testing (adversarial evaluation)
- [ ] Documented human oversight procedure

### 5.3 Additional Requirements for T1 (Critical)

All T1 and T2 requirements plus:

- [ ] **Algorithmic Impact Assessment** (Chapter 16 AIA Policy)
- [ ] **Data Protection Impact Assessment** (GDPR Art.35 if personal data)
- [ ] EU AI Act conformity assessment (Art.43) if applicable
- [ ] Bias mitigation plan with residual DPD/EOD documented
- [ ] Right-to-explanation mechanism (GDPR Art.22 / EU AI Act Art.13)
- [ ] CISO and DPO sign-off before deployment
- [ ] Quarterly fairness review
- [ ] Regulatory notification plan in place (resource 17.B)
- [ ] Full AI IRP integration (resource 17.A)

---

## 6. The AI Governance Lifecycle

### 6.1 Phase 1: Concept and Registration

**Gate:** AI System registered and classified before any development or procurement begins.

- Business owner raises **AI System Registration Form**
- AI Ethics Lead confirms classification
- Legal confirms applicable regulatory requirements
- Entry created in **AI System Inventory**

### 6.2 Phase 2: Design and Procurement

**Gate:** Security and privacy requirements defined and accepted before build or procurement begins.

- Security requirements documented from **Regulatory Mapping Matrix** (this template)
- DPIA commenced for T1 systems processing personal data
- Supply chain due diligence for procured models (resource 8.C)
- Fairness requirements specification (resource 16.F-2)

### 6.3 Phase 3: Development and Testing

**Gate:** Evidence package assembled and reviewed before deployment approval.

- Evidence collected against required controls (resource 14.A)
- Fairness evaluation completed (resource 16.A)
- Security testing completed (adversarial, supply chain, infrastructure)
- Model card generated (resource 12.B)
- AIA completed (T1 systems)

### 6.4 Phase 4: Deployment Approval

**Gate:** Sign-off obtained from all required approvers before production deployment.

| System Tier | Required Approvers |
|-------------|------------------|
| T1 | SRO + CISO + DPO + AI Ethics Lead + Legal |
| T2 | SRO + CISO + AI Ethics Lead |
| T3 | SRO + ML Lead |
| T4 | ML Lead |

All approvals documented in the **AI System Deployment Record**.

### 6.5 Phase 5: Production Operation

**Gate:** Monitoring is active and alerts are being reviewed before system is considered fully operational.

- Production fairness monitoring active (resource 16.D)
- Model drift detection active (resource 10.A)
- Access controls reviewed and confirmed
- Incident response runbook assigned (resource 17.F)

### 6.6 Phase 6: Review and Re-certification

- **T1 systems:** Annual full re-assessment; immediate re-assessment on material change
- **T2 systems:** Annual review; re-assessment on significant model or data change
- **T3/T4 systems:** Biennial review

**Material changes triggering immediate re-classification review:**
- New use case or population
- New protected attribute in training data or features
- Change in deployment jurisdiction
- Significant model architecture change
- Post-incident remediation

### 6.7 Phase 7: Decommission

- [ ] Data retention and deletion plan executed
- [ ] Model artefacts securely deleted or archived per retention policy
- [ ] Access revoked
- [ ] System removed from AI System Inventory (status: decommissioned)
- [ ] Any outstanding incidents or regulatory obligations confirmed closed

---

## 7. Accountability Structure

### 7.1 Roles and Responsibilities

| Role | Responsibilities |
|------|----------------|
| **Board / Risk Committee** | Ultimate accountability for AI risk appetite; receives quarterly AI risk summary |
| **CEO** | Executive sponsor of AI governance programme |
| **CISO** | Owns AI security policy; approves T1/T2 deployments; leads AI security incident response |
| **DPO** | Owns GDPR compliance for AI; conducts DPIAs; approves T1 deployments |
| **AI Ethics Lead** | Owns fairness, bias, and AIA processes; approves T1/T2 deployments |
| **Legal** | Regulatory compliance advice; approves T1 deployments; regulatory notifications |
| **Senior Responsible Owner (SRO)** | Business accountability for individual AI system; deployment gate approver |
| **ML Lead** | Technical ownership of AI systems; responsible for implementing security controls |
| **ML Ops** | Responsible for production monitoring, deployment automation, and incident first response |
| **Data Steward** | Responsible for data quality, lineage, and governance for training data |
| **Internal Audit** | Periodic audit of AI governance compliance; reports to Board |

### 7.2 Escalation

| Situation | Escalate To | Within |
|-----------|------------|-------|
| T1 system failing fairness threshold | AI Ethics Lead + CISO | 24 hours |
| AI security incident (P1/P2) | CISO + DPO | 2 hours |
| Regulatory inquiry regarding AI | Legal + DPO + CISO | 4 hours |
| Critical risk identified in AI Risk Register | CISO + SRO | 24 hours |
| Proposed AI system cannot be classified | AI Ethics Lead + Legal | 5 business days |

---

## 8. Compliance and Assurance

### 8.1 AI System Inventory

The organisation maintains an **AI System Inventory** recording all AI systems in scope. Each entry includes: system name, version, classification tier, SRO, deployment status, last assessment date, and key risk identifiers.

The Inventory is reviewed quarterly by the CISO and AI Ethics Lead.

### 8.2 Evidence Collection

Evidence of control implementation is collected using resource 14.A (`evidence_artefact.py`, `evidence_package_builder.py`) and mapped to controls using resource 14.B (`control_mapper.py`).

### 8.3 Maturity Assessment

Annual AI security maturity assessment conducted using resource 14.B (`maturity_scorer.py`, `gap_analyser.py`). Results reported to Board Risk Committee.

### 8.4 Internal Audit

Internal Audit conducts an annual review of AI governance compliance across a sample of T1 and T2 systems. Findings are tracked in the AI Risk Register.

### 8.5 Non-Compliance

| Non-Compliance | Consequence |
|---------------|------------|
| Deploying T1/T2 system without required approvals | Immediate deployment suspension; root cause within 5 days |
| Not completing AIA for T1 system | Deployment freeze; escalation to CISO and CEO |
| Missing fairness evaluation | Deployment freeze |
| Failure to report AI security incident | Disciplinary action per HR policy |

---

## 9. Policy Review

This policy is reviewed annually or upon material change to the regulatory landscape, organisational structure, or AI risk profile.

| Version | Date | Author | Approver | Changes |
|---------|------|--------|----------|---------|
| 1.0 | | | | Initial policy |

---

*Template: AI Fortress Chapter 14 · Modo Bhaik*
