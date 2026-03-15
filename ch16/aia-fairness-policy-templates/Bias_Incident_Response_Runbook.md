# Bias Incident Response Runbook
## AI Fortress — Chapter 16 Template 16.F-3

**Type:** Operational Runbook  
**Trigger:** Fairness alert, user complaint, regulatory inquiry, or external disclosure  
**Owner:** AI Ethics Lead / CISO  
**Version:** 1.0

---

## Overview

A bias incident is any situation where an AI system's outputs exhibit or are alleged to exhibit unfair discrimination against individuals based on protected attributes. This runbook provides step-by-step response procedures.

**Severity tiers:**

| Tier | Criteria | Response SLA |
|------|----------|-------------|
| **P1 — Critical** | Regulatory inquiry, media coverage, or DPD > 2× threshold | 2 hours to acknowledge; 24 hours to initial assessment |
| **P2 — High** | Automated fairness alert CRITICAL or confirmed user complaint | 4 hours to acknowledge; 48 hours to initial assessment |
| **P3 — Medium** | Automated fairness alert ALERT | 1 business day to acknowledge; 5 business days to assessment |
| **P4 — Low** | Automated fairness alert WARNING, internal flag | 5 business days to acknowledge; sprint to assess |

---

## Phase 1: Detection & Triage (T+0 to T+2h for P1/P2)

### Step 1.1 — Incident Declaration

- [ ] Assign Incident Commander (AI Ethics Lead or on-call CISO)
- [ ] Open incident ticket; record: system name, version, alert type, detection source, timestamp
- [ ] Classify severity tier (P1–P4) using table above
- [ ] Notify stakeholders per communication matrix (Section 7)

### Step 1.2 — Initial Evidence Collection

- [ ] Pull parity tracker history for affected system (resource 16.D parity_tracker.py)
- [ ] Download fairness alert log (resource 16.D alert_engine.py)
- [ ] Identify affected time window and estimated affected population
- [ ] Determine whether issue is: model drift, data drift, or pre-existing bias now detected
- [ ] Preserve model version, weights, and inference logs (immutable copy)

### Step 1.3 — Rapid Impact Assessment

Answer the following within the triage window:

| Question | Answer |
|----------|--------|
| Which protected group(s) are affected? | |
| What is the nature of the harm (denial, higher rates, lower quality)? | |
| How many individuals are estimated to be affected? | |
| Is the system still live and generating new decisions? | ☐ Yes ☐ No |
| Is there a regulatory reporting obligation? | ☐ Yes ☐ No ☐ TBD |
| Is a model pause required? | ☐ Yes ☐ No ☐ TBD |

---

## Phase 2: Containment (T+2h to T+24h for P1/P2)

### Step 2.1 — Containment Decision

| Option | When to Apply | Owner |
|--------|--------------|-------|
| **Full pause** — halt all automated decisions | P1: DPD > 2× threshold, ongoing harm | CISO + Product Owner |
| **Partial pause** — human review of affected subgroup's decisions | P2: confirmed harm, scoped to subgroup | AI Ethics Lead |
| **Threshold adjustment** — apply per-group thresholds while fix is developed | P3/P4: mild violation, low risk | ML Lead |
| **Monitor only** — no operational change, accelerate fix | P4: Warning only, early detection | ML Lead |

**Decision recorded by:** _______________________  
**Decision rationale:** _______________________

### Step 2.2 — Affected Individual Identification

- [ ] Query decision logs for affected time window
- [ ] Identify individuals who received adverse decisions potentially influenced by bias
- [ ] Document: decision type, decision date, individual ID (pseudonymised), predicted value, actual outcome
- [ ] Legal review: determine if notification or redress is required

### Step 2.3 — Regulatory Notification Assessment (P1 only)

| Regulator | Notification Required? | Deadline | Notified By |
|-----------|----------------------|----------|------------|
| ICO (UK GDPR) | ☐ Yes ☐ No | 72h if personal data breach | DPO |
| Supervisory Authority (EU GDPR) | ☐ Yes ☐ No | 72h if personal data breach | DPO |
| Sector regulator (FCA, EBA, etc.) | ☐ Yes ☐ No | Per sector rules | Legal |
| Internal Data Governance | ☐ Yes (always) | Immediately | Incident Commander |

---

## Phase 3: Root Cause Analysis (T+24h to T+5 days)

### Step 3.1 — Fairness Re-evaluation

Run full fairness evaluation suite on the affected model and data:

```bash
# 1. Compute metrics on affected window
python -c "
from fairness_metrics import FairnessEvaluator
# Load y_true, y_pred, groups from decision log
result = FairnessEvaluator(dpd_threshold=0.05).evaluate(y_true, y_pred, groups)
print(result.summary())
"

# 2. Intersectional analysis
python -c "
from intersectional_fairness import IntersectionalFairnessEvaluator
# Load y_true, y_pred, attributes from decision log
result = IntersectionalFairnessEvaluator().evaluate(y_true, y_pred, attributes)
print(result.grade, result.worst_subgroup)
"
```

### Step 3.2 — Root Cause Categories

Identify which root cause(s) apply:

| Category | Check | Finding |
|----------|-------|---------|
| **Training data imbalance** | Group representation in training set | |
| **Label bias** | Ground truth labels differ by group (e.g. historical discrimination) | |
| **Feature proxy** | Non-protected feature is correlated with protected attribute | |
| **Model architecture** | Model structure amplifies spurious correlations | |
| **Distribution drift** | Production data distribution differs from training | |
| **Threshold disparity** | Single threshold applied uniformly to different distributions | |
| **Feedback loop** | Biased decisions reinforce biased future training data | |

### Step 3.3 — Timeline Reconstruction

Document the timeline of events:

| Event | Timestamp | Details |
|-------|-----------|---------|
| Last known-good fairness evaluation | | |
| Earliest indicator of bias | | |
| First automated alert fired | | |
| Incident declared | | |
| Containment applied | | |
| RCA completed | | |

---

## Phase 4: Remediation (T+5 to T+30 days)

### Step 4.1 — Mitigation Selection

Apply mitigations per Fairness Requirements Specification Section 5.
Document which mitigations were attempted and their outcomes:

| Mitigation | Applied | Pre-fix DPD | Post-fix DPD | Pass? |
|-----------|---------|------------|-------------|-------|
| Reweighing | ☐ Yes ☐ No | | | ☐ |
| Threshold optimisation | ☐ Yes ☐ No | | | ☐ |
| Adversarial debiasing | ☐ Yes ☐ No | | | ☐ |
| Data augmentation | ☐ Yes ☐ No | | | ☐ |

### Step 4.2 — Redress Plan

- [ ] Determine scope of affected decisions requiring review or reversal
- [ ] Legal sign-off on redress approach
- [ ] Communicate with affected individuals (per legal requirement)
- [ ] Implement redress (manual review, re-decision, compensation)
- [ ] Log all redress actions with outcome

### Step 4.3 — Remediated Model Validation

Before restoring automated decisions:

- [ ] Full fairness evaluation passes all thresholds
- [ ] AIA delta assessment completed (Chapter 16 AIA Policy Section 4)
- [ ] CISO + DPO sign-off obtained
- [ ] Monitoring thresholds tightened (50% of standard threshold for 90 days post-incident)

---

## Phase 5: Post-Incident Review (T+30 to T+45 days)

### Step 5.1 — Post-Incident Report

The post-incident report must include:

1. Incident timeline and severity
2. Root cause analysis findings
3. Affected population and harm description
4. Mitigation steps taken
5. Redress provided
6. Monitoring improvements implemented
7. Process improvements recommended

### Step 5.2 — Process Improvements

| Finding | Process Change | Owner | Due Date |
|---------|---------------|-------|---------|
| | | | |
| | | | |

### Step 5.3 — AIA Update

- [ ] Update system AIA with incident findings
- [ ] Revise fairness thresholds if appropriate
- [ ] Update monitoring plan
- [ ] Schedule earlier re-evaluation if warranted

---

## 6. Escalation Matrix

| Situation | Escalate To | Within |
|-----------|------------|-------|
| P1 incident | CISO + CEO + Board Risk Committee | 2 hours |
| Regulatory notification required | DPO + Legal + CEO | 4 hours |
| Media / public attention | Communications + CEO | Immediately |
| P2 incident | CISO + Product Owner | 4 hours |
| Redress required | Legal + DPO + Product Owner | 24 hours |

---

## 7. Communication Matrix

| Audience | When | Channel | Owner |
|----------|------|---------|-------|
| Internal engineering team | Always | Incident ticket | Incident Commander |
| CISO | P1/P2 immediately; P3/P4 within 24h | Direct message | AI Ethics Lead |
| DPO | When personal data / regulatory risk | Email + meeting | Incident Commander |
| Affected users | Per legal requirement | Formal letter / email | Legal |
| Regulator | Per regulatory requirement | Formal notification | DPO + Legal |
| Media / public | Only if legally required or unavoidable | Via Communications team | CEO + Comms |

---

## 8. Runbook Maintenance

| Role | Responsibility | Review Frequency |
|------|---------------|-----------------|
| AI Ethics Lead | Maintain runbook currency | After each incident; annually |
| CISO | Approve material changes | Upon revision |
| Legal | Review notification obligations | Annually or on regulatory change |

---

*Template: AI Fortress Chapter 16 · Modo Bhaik*
