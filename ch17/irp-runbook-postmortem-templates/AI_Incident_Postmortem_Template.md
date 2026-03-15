# AI Security Incident Postmortem
## AI Fortress — Chapter 17 Template 17.F-2

> **Blameless postmortems** focus on systemic causes, not individual blame.
> The goal is to learn, not to punish. All participants are expected to
> share information openly and without fear of attribution.

---

## Incident Header

| Field | Value |
|-------|-------|
| **Incident ID** | |
| **Title** | |
| **Severity** | ☐ P1-Critical ☐ P2-High ☐ P3-Medium ☐ P4-Low |
| **Category** | ☐ Model Integrity ☐ Data Security ☐ Supply Chain ☐ Inference Attack ☐ Availability ☐ Bias/Fairness ☐ Explainability ☐ Regulatory |
| **Affected System(s)** | |
| **Affected Population** | Estimated number of individuals impacted |
| **Detection Source** | ☐ Automated alert ☐ User report ☐ External researcher ☐ Regulator ☐ Internal audit ☐ Other: |
| **Incident Commander** | |
| **Postmortem Lead** | |
| **Postmortem Date** | |
| **Participants** | |

---

## Key Metrics

| Metric | Value |
|--------|-------|
| **Incident Start** | Date/time (UTC) |
| **Time to Detect (TTD)** | minutes |
| **Time to Contain (TTC)** | minutes |
| **Time to Recover (TTR)** | minutes |
| **Total Incident Duration** | minutes |
| **Decisions Affected** | count |
| **Regulatory Notifications Sent** | ☐ Yes ☐ No — count: |

---

## 1. Executive Summary

*(3–5 sentences: what happened, who was affected, what was the business and/or privacy impact, how was it resolved)*

---

## 2. Incident Timeline

> Populate using `resource 17.A timeline_builder.py` output. Key milestones in **bold**.

| Timestamp (UTC) | Event | Actor | Milestone |
|----------------|-------|-------|-----------|
| | | | ☐ |
| | | | ☐ |
| | | | ☐ |
| | | | ☐ |
| | | | ☐ |

**Key IR Milestones:**

| Milestone | Timestamp | Notes |
|-----------|-----------|-------|
| Incident start (earliest evidence) | | |
| **Detection** | | How was it detected? |
| Triage complete | | Severity confirmed |
| **Containment** | | What was contained and how? |
| Eradication | | Root cause removed |
| **Recovery** | | System restored to safe operation |
| Postmortem complete | | |

---

## 3. What Happened

*(Detailed technical narrative of the incident. Include: initial conditions, sequence of events, how the incident evolved, and what made it possible. Be specific about system states, model versions, and data involved.)*

---

## 4. Detection Analysis

**4.1 How was the incident detected?**

*(Source, alert type, manual observation?)*

**4.2 Were detection controls working as expected?**

| Control | Worked? | Notes |
|---------|---------|-------|
| Fairness monitoring alerts | ☐ Yes ☐ No ☐ N/A | |
| Model drift detection | ☐ Yes ☐ No ☐ N/A | |
| SIEM / anomaly alerts | ☐ Yes ☐ No ☐ N/A | |
| Log monitoring | ☐ Yes ☐ No ☐ N/A | |
| Attestation / integrity check | ☐ Yes ☐ No ☐ N/A | |
| Human review process | ☐ Yes ☐ No ☐ N/A | |

**4.3 Why wasn't this detected earlier?**

*(What gaps in detection controls allowed the issue to persist?)*

---

## 5. Root Cause Analysis

### 5.1 Five Whys

| Why # | Finding |
|-------|---------|
| Why 1 (immediate cause) | |
| Why 2 | |
| Why 3 | |
| Why 4 | |
| Why 5 (systemic / root cause) | |

### 5.2 Contributing Factors

Mark all that apply and provide evidence:

| Factor | Present? | Evidence |
|--------|----------|----------|
| Training data quality / representation gap | ☐ Yes ☐ No | |
| Inadequate pre-deployment testing | ☐ Yes ☐ No | |
| Missing fairness evaluation before deployment | ☐ Yes ☐ No | |
| No AIA conducted / incomplete AIA | ☐ Yes ☐ No | |
| Insufficient monitoring in production | ☐ Yes ☐ No | |
| Alert thresholds too loose | ☐ Yes ☐ No | |
| Delayed escalation / unclear ownership | ☐ Yes ☐ No | |
| Third-party / supply chain weakness | ☐ Yes ☐ No | |
| Insufficient access controls on model artefacts | ☐ Yes ☐ No | |
| Process not followed / undocumented exception | ☐ Yes ☐ No | |
| Tool or infrastructure failure | ☐ Yes ☐ No | |
| External adversarial action | ☐ Yes ☐ No | |
| Other: | ☐ Yes ☐ No | |

### 5.3 Root Cause Statement

*(1–3 sentences. Be concrete: "The root cause was X, enabled by Y, because Z was absent.")*

---

## 6. Impact Assessment

### 6.1 Technical Impact

| Dimension | Impact | Severity |
|-----------|--------|----------|
| Model decision quality | | |
| Data integrity | | |
| Service availability | | |
| Model/data confidentiality | | |

### 6.2 Individual / Privacy Impact

| Question | Answer |
|----------|--------|
| Were individuals adversely affected by biased/incorrect decisions? | ☐ Yes ☐ No |
| Was personal data exposed? | ☐ Yes ☐ No |
| Were protected groups disproportionately affected? | ☐ Yes ☐ No |
| Will any individuals receive redress? | ☐ Yes ☐ No |
| Nature of redress: | |

### 6.3 Regulatory Impact

| Regulation | Notified? | Notification Date | Reference |
|-----------|-----------|------------------|-----------|
| GDPR (EU SA) | ☐ Yes ☐ No ☐ N/A | | |
| ICO (UK) | ☐ Yes ☐ No ☐ N/A | | |
| EU AI Act Art.73 | ☐ Yes ☐ No ☐ N/A | | |
| HIPAA | ☐ Yes ☐ No ☐ N/A | | |
| FCA / sector | ☐ Yes ☐ No ☐ N/A | | |
| NIS2 | ☐ Yes ☐ No ☐ N/A | | |

---

## 7. Response Evaluation

### 7.1 What Went Well

*(Celebrate what worked: fast detection, effective escalation, good communication, tools that helped)*

- 
- 
- 

### 7.2 What Went Poorly

*(Be honest: where were the delays, confusion, gaps?)*

- 
- 
- 

### 7.3 Where Were We Lucky?

*(What could have been worse? What near-misses occurred?)*

- 
- 

---

## 8. Action Items

> Populate using `resource 17.C action_tracker.py`. Track to completion.

| ID | Action | Type | Owner | Due Date | Priority | Status |
|----|--------|------|-------|----------|----------|--------|
| A-01 | | ☐ Prevent ☐ Detect ☐ Respond ☐ Recover | | | ☐ P1 ☐ P2 ☐ P3 | ☐ Open |
| A-02 | | | | | | ☐ Open |
| A-03 | | | | | | ☐ Open |
| A-04 | | | | | | ☐ Open |
| A-05 | | | | | | ☐ Open |

**Summary:** __ prevention actions, __ detection actions, __ response actions, __ recovery actions

---

## 9. Lessons Learned

*(3–5 key lessons that apply beyond this incident — to be shared with wider team and incorporated into training)*

1. 
2. 
3. 
4. 
5. 

---

## 10. Process and Policy Updates Required

| Update | Document | Owner | Due |
|--------|----------|-------|-----|
| | | | |
| | | | |

---

## 11. Sign-Off

| Role | Name | Date |
|------|------|------|
| Incident Commander | | |
| Postmortem Lead | | |
| CISO | | |
| DPO (if privacy impact) | | |

**Distribution:** CISO, ML Security Lead, ML Ops Lead, DPO (if applicable), relevant regulatory body (if required)

---

*Template: AI Fortress Chapter 17 · Modo Bhaik*
