# AI Security Incident Response Plan (IRP) — Runbook
## AI Fortress — Chapter 17 Template 17.F-1

**Type:** Operational Runbook  
**Owner:** CISO / AI Security Lead  
**Version:** 1.0  
**Review:** After each P1/P2 incident; annually otherwise

---

## 1. Purpose & Scope

This runbook operationalises the AI Security Incident Response Plan. It provides step-by-step procedures for detecting, triaging, containing, eradicating, and recovering from AI security incidents.

**Scope:** All AI/ML systems in production or pre-production, including:
- ML model training pipelines and serving infrastructure
- Training datasets and feature stores
- Model registries and artefact stores
- Edge AI and embedded ML devices
- AI APIs and inference endpoints

---

## 2. Severity & Response SLAs

| Severity | Definition | Acknowledge | Initial Assessment | Containment Target |
|----------|-----------|-------------|-------------------|-------------------|
| **P1 — Critical** | Active attack; confirmed exfiltration; high-risk AI system producing harmful decisions; regulatory breach | 15 min | 1 hour | 4 hours |
| **P2 — High** | Confirmed model/data compromise; privacy breach; fairness violation confirmed at scale | 30 min | 4 hours | 12 hours |
| **P3 — Medium** | Suspected breach; anomaly confirmed; threshold breached | 2 hours | 8 hours | 48 hours |
| **P4 — Low** | IOC detected; near-miss; warning alert | 1 business day | 5 business days | Next sprint |

---

## 3. Incident Response Team (IRT)

| Role | Responsibility | Escalation |
|------|---------------|-----------|
| **Incident Commander** | Overall coordination; decisions; external comms | CISO |
| **ML Security Lead** | Technical investigation; model/data forensics | Incident Commander |
| **DPO / Privacy Officer** | Privacy impact; regulatory notification | Legal |
| **Legal** | Regulatory obligations; external notification | General Counsel |
| **ML Ops Lead** | System isolation; rollback; restoration | Incident Commander |
| **Communications** | Internal and external communications (P1/P2 only) | CEO |
| **AI Ethics Lead** | Fairness incidents; bias assessment | CISO |

**On-call contacts:** *(insert on-call rotation / PagerDuty escalation policy)*

---

## 4. Phase 1 — Detection & Triage

### 4.1 Detection Sources

| Source | Incident Types Covered |
|--------|----------------------|
| Production fairness monitor (resource 16.D) | Fairness drift, demographic parity violation |
| Model integrity monitor | Weight tampering, hash mismatch |
| Privacy audit suite (resource 13.D) | Membership inference, canary exposure |
| SIEM / SOC alerts | Infrastructure compromise, anomalous API access |
| User complaint / report | Discriminatory output, incorrect decision |
| Third-party disclosure | Responsible disclosure, bug bounty |
| Automated security scan | Vulnerability in model serving stack |
| Regulatory inquiry | External triggered investigation |

### 4.2 Triage Steps

- [ ] **T+0** — Acknowledge alert / report
- [ ] **T+0** — Classify using resource 17.A `incident_classifier.py`; assign severity P1–P4
- [ ] **T+0** — Notify Incident Commander and roles per Section 3
- [ ] **T+0** — Open incident ticket; assign ID (format: INC-YYYY-NNN)
- [ ] **T+15m** — Confirm or revise severity; trigger playbook
- [ ] **T+15m** — Activate SeverityEscalator (resource 17.A); begin monitoring for escalation triggers
- [ ] **T+30m** — Check regulatory notification obligations (resource 17.B `obligation_checker.py`)
- [ ] **T+30m** — Start deadline tracker if notification required (resource 17.B `deadline_tracker.py`)

---

## 5. Phase 2 — Containment

### 5.1 Immediate Containment Actions (P1/P2)

| Action | Tool / Resource | Owner |
|--------|----------------|-------|
| Suspend automated decisions from affected model | Model serving kill-switch | ML Ops |
| Revoke API keys and rotate secrets | Secrets manager | Security |
| Quarantine affected training datasets | resource 17.D `data_quarantine_manager.py` | ML Ops |
| Isolate affected infrastructure | Cloud console / Terraform | Infrastructure |
| Preserve artefacts: model weights, logs, configs | resource 17.A `evidence_collector.py` | ML Security |
| Notify DPO if personal data involved | Direct | Incident Commander |

### 5.2 Containment Checklist

- [ ] Automated decisions suspended (or human oversight inserted)
- [ ] Affected API endpoints rate-limited or blocked
- [ ] Training pipeline paused
- [ ] Dataset quarantine in place
- [ ] Evidence collected and chained
- [ ] External access to model registry revoked
- [ ] Incident war room / bridge activated (P1 only)

---

## 6. Phase 3 — Investigation & Eradication

### 6.1 Evidence Collection

Use resource 17.A `evidence_collector.py`:

```bash
python -c "
from evidence_collector import EvidenceCollector
ec = EvidenceCollector('INC-YYYY-NNN', collector='ir-team')
# Collect model weights snapshot
ec.collect(open('model_v2.pkl','rb').read(), 'model_artefact', 'Potentially compromised weights')
# Collect inference log
ec.collect(open('inference.log','rb').read(), 'inference_log', 'Last 24h inference log')
chain = ec.verify_chain()
print(f'Chain valid: {chain.chain_valid}, items: {chain.item_count}')
"
```

### 6.2 Root Cause Analysis (RCA)

Run full RCA for each incident category:

| Category | RCA Steps |
|----------|----------|
| **Model integrity** | Diff model hash vs registry; check deployment pipeline for tampering |
| **Data poisoning** | Statistical analysis of training batch; label distribution; outlier detection |
| **Privacy breach** | Run membership inference audit (resource 13.D); canary exposure score |
| **Supply chain** | SBOM diff (resource 8); dependency hash verification |
| **Fairness incident** | Full fairness re-evaluation (resource 16.A); intersectional analysis |
| **Infrastructure** | Cloud trail audit; IAM access review; network flow analysis |

### 6.3 Eradication Steps

- [ ] Remove malicious model version from registry
- [ ] Re-train model from verified clean dataset (if poisoning confirmed)
- [ ] Patch vulnerability or misconfiguration
- [ ] Rotate all credentials in scope
- [ ] Purge poisoned data from all storage tiers
- [ ] Rebuild affected container images from scratch

---

## 7. Phase 4 — Recovery

### 7.1 Recovery Checklist (Before Restoring Automated Decisions)

Use resource 17.D `service_restoration_checker.py`:

```python
from service_restoration_checker import ServiceRestorationChecker
checker = ServiceRestorationChecker()
result  = checker.check("fraud-scoring-api", "INC-YYYY-NNN", {
    "model_integrity_verified":      {"passed": True,  "verified_by": "ml-security"},
    "vulnerability_patched":         {"passed": True,  "verified_by": "security-eng"},
    "fairness_evaluation_passed":    {"passed": False, "verified_by": "", "notes": "In progress"},
    "monitoring_alerts_configured":  {"passed": True,  "verified_by": "ml-ops"},
    "rollback_plan_in_place":        {"passed": True,  "verified_by": "ml-ops"},
    "incident_commander_approved":   {"passed": False, "verified_by": ""},
    "legal_dpo_cleared":             {"passed": False, "verified_by": ""},
    "penetration_test_passed":       {"passed": False, "verified_by": ""},
})
print(result.verdict, result.blocked_gates)
```

### 7.2 Model Rollback Procedure

If rollback to prior version required, use resource 17.D `model_rollback_orchestrator.py`:

1. Identify last blessed version in model registry
2. Verify weights hash against registry record
3. Obtain Incident Commander approval
4. Execute rollback with audit record
5. Validate restored model on representative test set
6. Re-run fairness evaluation (resource 16.A)
7. Confirm monitoring is active before restoring traffic

### 7.3 Post-Recovery Monitoring

For 30 days following P1/P2 incidents:
- Tighten fairness alert thresholds to 50% of standard
- Increase parity monitoring frequency (daily vs weekly)
- Enable enhanced inference logging
- Daily check-in from ML Security Lead

---

## 8. Phase 5 — Regulatory Notification

- [ ] Check obligations with resource 17.B `obligation_checker.py`
- [ ] Draft notifications with resource 17.B `notification_drafter.py`
- [ ] Legal review all drafts before submission
- [ ] Track deadlines with resource 17.B `deadline_tracker.py`
- [ ] Mark as submitted once sent
- [ ] File confirmation receipts in incident record

**Key deadlines to track:**

| Regulation | Deadline | Notifier |
|-----------|---------|---------|
| GDPR Art.33 | 72 hours | DPO |
| NIS2 Art.23 | 24h early warning | CISO |
| EU AI Act Art.73 | 15 working days | Provider |
| UK ICO | 72 hours | DPO |
| HIPAA | 60 days | Privacy Officer |
| SEC 8-K | 4 business days (material) | CFO + Legal |

---

## 9. Phase 6 — Postmortem

Mandatory for all P1/P2 incidents; strongly recommended for P3.

- [ ] Conduct blameless postmortem within 7 days of closure (P1/P2) or 30 days (P3)
- [ ] Identify root causes using resource 17.C `finding_extractor.py`
- [ ] Create action items in resource 17.C `action_tracker.py`
- [ ] Generate postmortem report using resource 17.C `postmortem_builder.py`
- [ ] Review lessons learned with wider team
- [ ] Update IRP runbook if process gaps identified
- [ ] Incorporate scenario into next tabletop exercise (resource 17.E)

---

## 10. Communication Templates

### P1 Internal Alert (T+15m)
> **[P1 INCIDENT ACTIVE — INC-YYYY-NNN]**  
> System: [system name]  
> Nature: [brief description]  
> Impact: [affected decisions / data / users]  
> Incident Commander: [name]  
> Bridge: [link]  
> All IRT members: join bridge immediately.

### User/Customer Notification (Draft — legal review required)
> We are writing to inform you that [SYSTEM NAME] experienced a security incident between [DATE] and [DATE]. [BRIEF DESCRIPTION OF NATURE AND IMPACT]. We have taken the following steps: [MITIGATIONS]. If you have questions, please contact [DPO CONTACT].

---

## 11. Runbook Maintenance

| Review Trigger | Reviewer | Timeline |
|----------------|---------|---------|
| After each P1/P2 incident | CISO + ML Security Lead | Within 30 days |
| Annual review | Full IRT | Annually |
| Regulatory change | Legal + DPO | Within 60 days |

---

*Template: AI Fortress Chapter 17 · Mohan Krishnamurthy*
