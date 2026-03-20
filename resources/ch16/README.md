# AI Fortress — Chapter 16 Code Resources
## Fairness, Bias, & Explainability

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 16 of 17

---

## Resources in This Package

| ID | Folder | Type | Description |
|----|--------|------|-------------|
| 16.A | `fairness-evaluation/` | Code | Fairness metric suite: demographic parity, equalised odds, individual fairness, and calibration gap across protected groups |
| 16.B | `bias-mitigation/` | Code | Bias mitigation: pre-processing reweighing, in-processing adversarial debiasing stub, post-processing threshold optimiser |
| 16.C | `aia-toolkit/` | Code | Algorithmic Impact Assessment toolkit: impact register, stakeholder impact scorer, regulatory classification checker |
| 16.D | `fairness-monitoring/` | Code | Production fairness monitoring: drift-aware parity tracker, alert engine, fairness dashboard data builder |
| 16.E | `explainability/` | Code | Explainability: SHAP-style feature importance approximation, counterfactual generator, explanation auditor |
| 16.F | `aia-fairness-policy-templates/` | Templates | AIA policy, fairness requirements specification, and bias incident response runbook |

---

## Quick Setup

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Fairness Metric Reference

| Metric | Formula | Fairness Satisfied When |
|--------|---------|------------------------|
| Demographic Parity | P(Ŷ=1\|A=0) = P(Ŷ=1\|A=1) | Selection rate equal across groups |
| Equalised Odds | TPR equal AND FPR equal across groups | Both error rates balanced |
| Equal Opportunity | TPR(A=0) = TPR(A=1) | True positive rate equal |
| Calibration | P(Y=1\|score=s, A=0) = P(Y=1\|score=s, A=1) | Same score means same risk |
| Individual Fairness | sim(x,x') high ⟹ d(f(x),f(x')) low | Similar people treated similarly |

---

## Regulatory Context (Chapter 16)

- **EU AI Act Art. 10**: Training data must be free from bias for high-risk systems
- **EU AI Act Art. 13**: Transparency and explainability requirements
- **EU AI Act Art. 29**: Human oversight, including explanation of decisions
- **GDPR Art. 22**: Right to explanation for automated decisions
- **Equal Credit Opportunity Act / Fair Housing Act**: US protected class requirements
- **IEEE 7000-2021**: Model process for addressing ethical concerns

---

## Companion Site

**https://[your-domain]/resources/ch16**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
