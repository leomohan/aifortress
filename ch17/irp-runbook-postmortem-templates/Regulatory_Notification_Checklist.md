# Regulatory Notification Checklist
## AI Fortress — Chapter 17 Template 17.F-3

**Use this checklist immediately upon confirming an AI security incident.**  
**Tool support:** `resource 17.B obligation_checker.py` and `notification_drafter.py`

---

## Step 1: Notification Obligation Triage

Answer each question. A "Yes" triggers the corresponding notification path.

| # | Question | Yes/No | Notification Path |
|---|----------|--------|-----------------|
| 1 | Does the incident involve personal data of EU/EEA residents? | | GDPR Art.33 → Section 2A |
| 2 | Is there a high risk to rights/freedoms of EU/EEA individuals? | | GDPR Art.34 → Section 2B |
| 3 | Does the incident involve personal data of UK residents? | | UK GDPR / ICO → Section 2C |
| 4 | Is the affected system a high-risk AI under EU AI Act Annex III? | | EU AI Act Art.73 → Section 2D |
| 5 | Does the incident involve PHI (US healthcare data)? | | HIPAA Breach Rule → Section 2E |
| 6 | Is the organisation a UK-regulated financial firm? | | FCA SYSC → Section 2F |
| 7 | Is the organisation subject to NIS2 (EU critical infrastructure)? | | NIS2 → Section 2G |
| 8 | Is the organisation a US publicly listed company? | | SEC Material Event → Section 2H |

---

## Section 2A: GDPR Art.33 — Notification to Supervisory Authority

**Trigger:** Personal data breach involving EU/EEA residents  
**Deadline:** Within 72 hours of becoming aware  
**To:** Lead Supervisory Authority (LSA) — the SA in the member state of your EU establishment

### Checklist

- [ ] **T+0** — Confirm breach meets Art.4(12) definition: accidental/unlawful destruction, loss, alteration, unauthorised disclosure of or access to personal data
- [ ] **T+0** — Assign DPO as notification lead
- [ ] **T+4h** — Establish: categories and approximate number of individuals concerned; categories and approximate number of records concerned
- [ ] **T+8h** — Establish: name/contact of DPO; likely consequences of the breach; measures taken or proposed to address the breach
- [ ] **T+48h** — Draft notification using `resource 17.B notification_drafter.py` with regulation="gdpr_art33"
- [ ] **T+72h** — Submit notification to LSA via SA's online portal
- [ ] **T+72h** — Log submission reference number in incident record
- [ ] **Post-72h** — If all information not available at T+72h: submit partial notification and phase-in remaining details

**If notifying after 72h:**
- [ ] Include written explanation for delay
- [ ] Attach all supporting evidence

**Content required (Art.33(3)):**
- Nature of the breach (categories and approximate number of individuals and records)
- Contact details of DPO
- Likely consequences of the breach
- Measures taken/proposed to address the breach, including mitigation

---

## Section 2B: GDPR Art.34 — Communication to Data Subjects

**Trigger:** High risk to rights and freedoms of natural persons  
**Deadline:** Without undue delay  
**To:** Affected individuals directly

### Checklist

- [ ] Assess whether the breach is "likely to result in a high risk" to individuals
- [ ] Identify all affected individuals with contact information
- [ ] Draft plain-language communication explaining:
  - [ ] Nature of the breach
  - [ ] Contact details of DPO
  - [ ] Likely consequences
  - [ ] Measures taken
  - [ ] Advice to affected individuals (e.g. change passwords, monitor accounts)
- [ ] Legal review of communication
- [ ] Send via direct channel (email, letter, prominent website notice if direct contact not possible)
- [ ] Log all notifications with timestamps and recipient IDs (pseudonymised)
- [ ] **Exemptions check** (Art.34(3)): no notification required if:
  - [ ] Appropriate technical/organisational protection measures implemented (e.g. encryption)
  - [ ] Subsequent measures have ensured high risk no longer likely to materialise
  - [ ] Communication would involve disproportionate effort (→ public communication required instead)

---

## Section 2C: UK GDPR / ICO Notification

**Trigger:** Personal data breach of UK residents  
**Deadline:** Within 72 hours of becoming aware  
**To:** Information Commissioner's Office (ICO)  
**Portal:** https://ico.org.uk/for-organisations/report-a-breach/

### Checklist

- [ ] Confirm breach threshold: likely to result in a risk to individuals' rights and freedoms
- [ ] Assign DPO as notification lead
- [ ] Draft notification (mirrors GDPR Art.33 content requirements)
- [ ] Submit via ICO online portal within 72 hours
- [ ] Note: UK GDPR applies to UK establishment or UK resident data; GDPR applies to EU establishment or EU resident data — both may apply
- [ ] Log ICO reference number

---

## Section 2D: EU AI Act Art.73 — Serious Incident Notification

**Trigger:** Serious incident involving a high-risk AI system (EU AI Act Annex III)  
**Deadline:** 15 days after becoming aware (Art.73(1))  
**To:** Market surveillance authority of the member state where incident occurred

**Definition of "serious incident" (Art.3(49)):**
Any incident that directly or indirectly led, or could have led to:
- Death or serious harm to health/safety
- Serious and irreversible disruption to management of critical infrastructure
- Infringement of fundamental rights
- Serious damage to property or environment

### Checklist

- [ ] Confirm system is high-risk under Annex III
- [ ] Assess whether incident meets Art.3(49) serious incident definition
- [ ] **T+0** — Notify AI system deployer (if you are the provider)
- [ ] **T+15 days** — Submit report to market surveillance authority including:
  - [ ] Description of the AI system and its version
  - [ ] Description of the incident, including its effects and the measures taken
  - [ ] Information about persons responsible
  - [ ] Corrective action taken or planned
- [ ] Record incident in post-market monitoring system (Art.72)
- [ ] If personal data breach also occurred: coordinate with GDPR notification (72h deadline takes priority)

---

## Section 2E: HIPAA Breach Notification Rule

**Trigger:** Breach of unsecured Protected Health Information (PHI)  
**Deadlines:**
- Individuals: within 60 days of discovery
- HHS Secretary: within 60 days of calendar year end (< 500 persons) OR within 60 days of discovery (≥ 500 persons)
- Media (≥ 500 in state/jurisdiction): within 60 days of discovery

### Checklist

- [ ] Confirm breach involves unsecured PHI (not encrypted/destroyed per NIST standards)
- [ ] Conduct breach risk assessment (4-factor test): nature/extent of PHI; who used/disclosed; whether acquired/viewed; risk of harm
- [ ] If risk assessment indicates low probability of compromise → document and no notification required
- [ ] If notification required:
  - [ ] Identify all affected individuals
  - [ ] Draft individual notification (content requirements: description of breach, types of PHI involved, steps individuals should take, steps covered entity is taking, contact information)
  - [ ] Send to affected individuals within 60 days
  - [ ] Submit to HHS Secretary (hhs.gov/ocr/breach) within required timeframe
  - [ ] If ≥ 500 in state: notify prominent media outlets in the state
- [ ] Log all notifications with dates in breach notification log

---

## Section 2F: FCA SYSC — UK Financial Conduct Authority

**Trigger:** Material operational incident at FCA-authorised firm  
**Deadline:** As soon as reasonably practicable after becoming aware  
**To:** FCA Supervision team

### Checklist

- [ ] Assess materiality: significant adverse effect on operations, systems, or delivery of services to customers
- [ ] **T+0** — Initial notification to FCA supervisor (telephone + email)
- [ ] **T+24h** — Follow-up written notification via FCA Connect portal
- [ ] Include: description of incident, impact on customers and operations, actions taken, timeline for resolution
- [ ] Continue to update FCA as material developments occur
- [ ] Final notification when incident resolved with root cause and remediation

---

## Section 2G: NIS2 Directive — EU Cybersecurity Incident

**Trigger:** Significant incident affecting essential or important entities  
**Deadlines:**
- Early warning: within 24 hours of becoming aware
- Incident notification: within 72 hours
- Final report: within 1 month
**To:** National CSIRT and/or competent authority

**"Significant incident" (Art.23(3)):** caused or may cause severe operational disruption or financial losses; or affected/may affect other organisations

### Checklist

- [ ] **T+24h** — Submit early warning to national CSIRT (whether incident suspected to be caused by unlawful or malicious act, cross-border impact)
- [ ] **T+72h** — Submit incident notification including:
  - [ ] Updated assessment of incident (severity/impact)
  - [ ] Indicators of compromise (if available)
- [ ] **T+1 month** — Submit final report:
  - [ ] Detailed description of incident
  - [ ] Type of threat / root cause
  - [ ] Applied and ongoing mitigation measures
  - [ ] Cross-border impact (if any)
- [ ] If ongoing incident at 1 month: submit progress report instead, final report within 1 month of handling

---

## Section 2H: SEC Material Cybersecurity Incident (US Public Companies)

**Trigger:** Determination that cybersecurity incident is material (Item 1.05 Form 8-K)  
**Deadline:** Within 4 business days of determining materiality  
**To:** SEC via EDGAR

### Checklist

- [ ] Board / Disclosure Committee makes materiality determination
- [ ] Prepare Form 8-K Item 1.05 disclosure:
  - [ ] Material aspects of nature, scope, and timing of incident
  - [ ] Material impact or reasonably likely material impact on registrant
- [ ] File with SEC within 4 business days
- [ ] Ongoing disclosure of material updates in subsequent filings

---

## Step 3: Coordination and Tracking

| Regulation | Lead | Notification Sent | Reference # | Close Date |
|-----------|------|------------------|-------------|-----------|
| GDPR Art.33 | DPO | ☐ Yes ☐ No ☐ N/A | | |
| GDPR Art.34 | DPO | ☐ Yes ☐ No ☐ N/A | | |
| UK GDPR / ICO | DPO | ☐ Yes ☐ No ☐ N/A | | |
| EU AI Act Art.73 | Legal + AI Ethics | ☐ Yes ☐ No ☐ N/A | | |
| HIPAA | Privacy Officer | ☐ Yes ☐ No ☐ N/A | | |
| FCA | Compliance | ☐ Yes ☐ No ☐ N/A | | |
| NIS2 | CISO | ☐ Yes ☐ No ☐ N/A | | |
| SEC 8-K | General Counsel | ☐ Yes ☐ No ☐ N/A | | |

**All notifications reviewed by:** _______________________ **Date:** _______

---

## Step 4: Post-Notification

- [ ] File copies of all notifications in incident record
- [ ] Track regulator follow-up requests and respond within required timeframes
- [ ] Provide regulator with incident postmortem report when complete (resource 17.F-2)
- [ ] Update Data Breach Register (GDPR Art.33(5) record-keeping requirement)
- [ ] Schedule regulatory follow-up meeting if required

---

*Template: AI Fortress Chapter 17 · Modo Bhaik*
