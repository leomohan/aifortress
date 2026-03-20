# Fairness Requirements Specification
## AI Fortress — Chapter 16 Template 16.F-2

**System:** ___________________________________  
**Version:** ___________________________________  
**Protected Attribute(s):** ___________________________________  
**Use Case:** ___________________________________  
**Author:** ___________________________________  
**Date:** ___________________________________

---

## 1. Fairness Objectives

State the specific fairness goals for this system. Be explicit about which metrics are binding requirements vs. aspirational targets.

| # | Objective | Metric | Binding? |
|---|-----------|--------|---------|
| F-01 | | | ☐ Required ☐ Target |
| F-02 | | | ☐ Required ☐ Target |
| F-03 | | | ☐ Required ☐ Target |

**Rationale for chosen metrics:**

> *(Explain why these metrics were chosen over alternatives, given the use case and legal context. E.g.: "Equalised odds was chosen over demographic parity because the base rate of the outcome differs significantly across groups and equal treatment requires equal error rates.")*

---

## 2. Protected Attributes

| Attribute | Values / Categories | Source in Data | Legal Basis |
|-----------|--------------------|--------------|-----------| 
| | | | GDPR Art.9 / ECOA / Other: |
| | | | |

**Intersectional analysis required?** ☐ Yes ☐ No  
**Reason:** ___________________________________

---

## 3. Fairness Thresholds

These are the numerical pass/fail gates. Values should be justified against legal requirements, business context, and literature.

| Metric | Threshold | Justification |
|--------|-----------|-------------|
| Demographic Parity Difference (DPD) | ≤ | |
| Equalised Odds Difference (EOD) | ≤ | |
| Equal Opportunity Difference (EOpD) | ≤ | |
| Predictive Parity Difference (PPD) | ≤ | |
| Calibration Gap | ≤ | |
| Intersectional parity range | ≤ | |

**Threshold notes:**  
- The 80% rule (4/5ths rule) for adverse impact under US employment law implies DPD ≤ 0.20 on the positive selection rate ratio. Many organisations adopt a stricter internal threshold of 0.10.
- EU AI Act does not specify numeric thresholds; thresholds above are internal policy.
- Thresholds should be revisited if the base rate changes significantly between groups.

---

## 4. Evaluation Dataset Requirements

| Requirement | Specification |
|-------------|--------------|
| Minimum samples per group | |
| Minimum samples per intersectional subgroup | |
| Time period for evaluation data | |
| Data freshness requirement | |
| Held-out vs. production data | ☐ Held-out test set ☐ Production sample ☐ Both |
| Ground truth label quality check | ☐ Required ☐ Not required |

---

## 5. Mitigation Priority Order

When fairness violations are detected, apply mitigations in this order:

| Priority | Mitigation | Condition | Tool |
|----------|-----------|-----------|------|
| 1 | Pre-processing: reweighing | Representation imbalance in training data | resource 16.B reweighing.py |
| 2 | Post-processing: threshold optimisation | Equal opportunity or parity gap | resource 16.B threshold_optimizer.py |
| 3 | In-processing: adversarial debiasing | Persistent violation after pre/post-processing | resource 16.B adversarial_debiasing_stub.py |
| 4 | Data collection: targeted augmentation | Insufficient data for minority group | Data team |
| 5 | Model redesign | Structural bias in feature set | ML team + ethics review |

**Escalation:** If no mitigation reduces violation below threshold after 3 attempts, escalate to AI Ethics Lead and CISO before proceeding.

---

## 6. Explainability Requirements

| Requirement | Specification |
|-------------|--------------|
| Explanation method | ☐ SHAP ☐ LIME ☐ Counterfactual ☐ Rule-based ☐ Other: |
| Minimum consistency score | ≥ |
| Completeness tolerance (SHAP sum error) | ≤ |
| Explanation fairness gap | ≤ |
| Affected individuals' right to explanation | ☐ Required (GDPR Art.22) ☐ Not required |
| Explanation format for end users | ☐ Natural language ☐ Feature importance list ☐ Counterfactual ☐ All |

---

## 7. Ongoing Monitoring Requirements

| Metric | Frequency | Alert Threshold | Owner |
|--------|-----------|----------------|-------|
| Demographic parity (production) | | | |
| Equalised odds (production) | | | |
| Explanation consistency | | | |
| Data distribution drift | | | |

---

## 8. Acceptance Criteria Summary

The system **passes** fairness evaluation if ALL of the following are true:

- [ ] All required fairness metrics are within their thresholds (Section 3)
- [ ] Intersectional analysis conducted (if required, Section 2)
- [ ] No single subgroup has parity range > intersectional threshold
- [ ] Explanation audit passes (Section 6)
- [ ] Monitoring plan is in place (Section 7)

---

## 9. Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| ML Lead | | | |
| AI Ethics Lead | | | |
| Product Owner | | | |
| Legal / DPO | | | |

---

*Template: AI Fortress Chapter 16 · Mohan Krishnamurthy*
