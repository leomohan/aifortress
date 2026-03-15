# AI Fortress — Chapter 17 Code Resources
## AI Security Incident Response

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Modo Bhaik  
**Chapter:** 17 of 17 — FINAL CHAPTER

---

## Resources in This Package

| ID | Folder | Type | Description |
|----|--------|------|-------------|
| 17.A | `incident-response-toolkit/` | Code | AI-specific incident classifier, evidence collector, and IR workflow engine |
| 17.B | `regulatory-notification/` | Code | Regulatory notification generator: GDPR, EU AI Act, sector-specific (FCA, ICO, HHS) |
| 17.C | `postmortem-automation/` | Code | Automated postmortem builder: timeline reconstruction, contributing factors, action items |
| 17.D | `recovery-playbooks/` | Code | Recovery playbook executor: model rollback, data quarantine, service restoration |
| 17.E | `tabletop-exercises/` | Code | Tabletop exercise scenario generator and facilitator scoring system |
| 17.F | `irp-runbook-postmortem-templates/` | Templates | AI IRP master runbook, postmortem template, and regulatory notification checklist |

---

## Quick Setup

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## AI Incident Taxonomy (Chapter 17)

| Category | Examples | Primary Impact |
|----------|---------|----------------|
| **Model Integrity** | Adversarial attack, model poisoning, watermark removal | Decision quality |
| **Data Security** | Training data exfiltration, PII exposure, dataset poisoning | Privacy + model quality |
| **Supply Chain** | Compromised pre-trained model, malicious dependency | Model trustworthiness |
| **Inference Attack** | Model inversion, membership inference, extraction | Privacy |
| **Availability** | Model API DoS, GPU resource exhaustion | Service continuity |
| **Bias / Fairness** | Detected discrimination, fairness drift, bias incident | Legal + reputational |
| **Explainability Failure** | Right-to-explanation breach, opaque decision | Regulatory |
| **Regulatory** | EU AI Act violation, GDPR Art.22 breach | Compliance |

---

## IR Lifecycle (Chapter 17)

```
Detect -> Triage -> Contain -> Investigate -> Remediate -> Recover -> Post-Incident
  |         |         |            |               |           |           |
17.A     17.A      17.D       17.A+17.C          17.D        17.D      17.C+17.F
```

---

## Regulatory Notification Timelines

| Regulation | Trigger | Deadline |
|-----------|---------|----------|
| EU GDPR Art.33 | Personal data breach | 72 hours to SA |
| EU GDPR Art.34 | High-risk to individuals | Without undue delay |
| EU AI Act Art.73 | Serious incident (high-risk AI) | 15 days |
| UK GDPR / DPA 2018 | Personal data breach | 72 hours to ICO |
| HIPAA Breach Rule | PHI breach >= 500 persons | 60 days |
| FCA SYSC 8.4 | Material operational incident | Immediately practicable |
| NIS2 Directive | Significant incident | 24h early warning; 72h report |

---

## Companion Site

**https://[your-domain]/resources/ch17**

---

*AI Fortress. Modo Bhaik. For educational and professional use.*
