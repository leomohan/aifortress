# Ch.13-D — Privacy Audit Suite

**AI Fortress** · Chapter 13: Privacy-Preserving Machine Learning

---

## What This Does

Audits trained ML models for privacy leakage:

- **Membership inference simulator** — implements a shadow-model-style
  membership inference attack baseline; computes attack AUC and
  per-threshold TPR/FPR; a well-protected model should have AUC ≈ 0.5
- **Attribute inference risk scorer** — estimates risk that an adversary
  can reconstruct a sensitive attribute from model predictions; uses
  a correlation proxy score as a risk indicator
- **Canary insertion auditor** — measures exposure of deliberately
  inserted canary records by tracking prediction confidence on canary
  vs non-canary records; computes exposure score per Carlini et al.
- **Audit report generator** — assembles all audit findings into a
  structured privacy audit report with severity ratings and
  remediation recommendations

---

## File Structure

```
privacy-audit-suite/
├── README.md
├── requirements.txt
├── membership_inference.py     # Shadow-model membership inference baseline
├── attribute_inference.py      # Attribute inference risk scoring
├── canary_auditor.py           # Canary insertion exposure measurement
├── audit_report.py             # Privacy audit report assembly
└── tests/
    └── test_privacy_audit.py
```
