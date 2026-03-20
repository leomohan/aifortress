# Algorithmic Impact Assessment Policy
## AI Fortress — Chapter 16 Template 16.F-1

**Standard:** EU AI Act, NIST AI RMF, IEEE 7000-2021  
**Version:** 1.0  
**Review Cycle:** Annual or upon material system change

---

## 1. Purpose and Scope

This policy establishes requirements for conducting Algorithmic Impact Assessments (AIAs) before deploying AI systems that may affect individuals' rights, opportunities, or welfare.

**Scope:** All AI systems that:
- Produce decisions or recommendations affecting individuals (employment, credit, healthcare, education, law enforcement)
- Process personal data of EU/EEA residents (GDPR Art.22 applicability)
- Are classified as high-risk under EU AI Act Annex III
- Affect more than 1,000 individuals per year

**Out of scope:** Internal operational tools with no individual-facing outputs.

---

## 2. Definitions

| Term | Definition |
|------|-----------|
| **AI System** | A machine-based system that generates outputs such as predictions, recommendations, decisions, or content influencing real or virtual environments |
| **High-Risk AI** | Systems listed in EU AI Act Annex III (biometric, employment, credit, education, law enforcement, migration, justice, critical infrastructure) |
| **Protected Attribute** | Characteristic protected under applicable law (race, sex, age, disability, religion, national origin, sexual orientation) |
| **AIA** | A structured assessment of an AI system's potential positive and negative impacts on individuals and communities |
| **DPIA** | Data Protection Impact Assessment (GDPR Art.35); required when processing is likely to result in high risk to natural persons |

---

## 3. AIA Requirement Triggers

An AIA is **mandatory** when any of the following conditions are met:

| Trigger | Threshold | AIA Level |
|---------|-----------|-----------|
| EU AI Act high-risk classification | Any Annex III match | Full AIA |
| GDPR Art.22 automated decision | Individual solely-automated decision with legal/significant effect | Full AIA + DPIA |
| Population scale | > 10,000 individuals/year | Full AIA |
| Sensitive use case | Employment, credit, healthcare, education, policing | Full AIA |
| Medium scale with uncertainty | 1,000–10,000 individuals/year | Abbreviated AIA |
| New protected-attribute features | Addition of any protected attribute to model | Delta AIA |

---

## 4. AIA Process

### 4.1 Phase 1: System Description (Weeks 1–2)

- [ ] Document system name, version, purpose, and use-case description
- [ ] Identify the decision or recommendation produced
- [ ] Map data flows: inputs, processing, outputs, downstream effects
- [ ] Identify affected populations and stakeholder groups
- [ ] Classify under EU AI Act (use resource 16.C regulatory_classifier.py)

### 4.2 Phase 2: Stakeholder Impact Analysis (Weeks 2–3)

- [ ] Score impacts across dimensions: autonomy, dignity, fairness, economic, safety, privacy (use resource 16.C stakeholder_impact_scorer.py)
- [ ] Conduct stakeholder consultation for high-impact groups
- [ ] Document impacts in the Impact Register (use resource 16.C impact_register.py)
- [ ] Identify disproportionate impacts on protected groups

### 4.3 Phase 3: Fairness & Bias Evaluation (Weeks 3–5)

- [ ] Define protected attributes for evaluation
- [ ] Compute demographic parity, equalised odds, equal opportunity metrics (use resource 16.A fairness_metrics.py)
- [ ] Conduct intersectional analysis (use resource 16.A intersectional_fairness.py)
- [ ] Apply bias mitigation if violations found (use resource 16.B)
- [ ] Document residual fairness risk with justification

### 4.4 Phase 4: Explainability Assessment (Week 5)

- [ ] Generate explanations for representative sample (use resource 16.E)
- [ ] Audit explanation consistency and completeness
- [ ] Verify affected individuals can receive meaningful explanation
- [ ] Document GDPR Art.22 right-to-explanation compliance plan

### 4.5 Phase 5: Risk Mitigation & Sign-Off (Week 6)

- [ ] Map all identified impacts to mitigations
- [ ] Determine residual risk level
- [ ] Obtain sign-off from Data Protection Officer (if DPIA required)
- [ ] Obtain sign-off from CISO and Senior Responsible Owner
- [ ] Schedule post-deployment monitoring (use resource 16.D)

---

## 5. AIA Documentation Requirements

Each completed AIA must include:

1. **Executive Summary** — purpose, classification, and deployment decision
2. **System Description** — technical and functional overview
3. **Stakeholder Impact Matrix** — output of phase 2
4. **Fairness Evaluation Report** — output of resource 16.A FairnessReportBuilder
5. **Bias Mitigation Record** — methods applied and residual DPD/EOD
6. **Explainability Audit** — output of resource 16.E ExplanationAuditor
7. **Regulatory Classification** — EU AI Act tier and compliance obligations
8. **Risk Register** — all identified impacts with mitigations and status
9. **Sign-Off Sheet** — approval signatures and date
10. **Monitoring Plan** — ongoing parity tracking cadence and alert thresholds

---

## 6. Approval Authority

| AIA Level | Required Approvers |
|-----------|-------------------|
| Full AIA | CISO + DPO + Product Owner + Legal |
| Abbreviated AIA | CISO + Product Owner |
| Delta AIA | ML Security Lead + Product Owner |

**Deployment Gate:** No AI system subject to this policy may be deployed to production without a completed, signed AIA.

---

## 7. Post-Deployment Monitoring Obligations

| Obligation | Frequency | Owner |
|-----------|-----------|-------|
| Parity metric check | Weekly (auto) | ML Ops |
| Fairness alert review | Monthly | AI Ethics Lead |
| Full re-evaluation | Annually or upon material change | AI Ethics + CISO |
| Stakeholder feedback review | Quarterly | Product Owner |
| Regulatory compliance check | Bi-annually | Legal + DPO |

A **material change** triggering re-evaluation includes: change in training data distribution, change in model architecture, new protected attribute in scope, new deployment context, or reported bias incident.

---

## 8. Non-Compliance

Failure to complete a required AIA before deployment constitutes a policy violation. Consequences:

- Immediate deployment freeze
- Root cause analysis within 5 business days
- Corrective AIA completion within 30 days
- Escalation to Board Risk Committee if material impact identified

---

## 9. Policy Owner and Review

| Role | Name | Review Date |
|------|------|------------|
| Policy Owner (AI Ethics Lead) | | |
| Approver (CISO) | | |
| Approver (DPO) | | |
| Next Review Date | | |

---

*Template: AI Fortress Chapter 16 · Mohan Krishnamurthy*
