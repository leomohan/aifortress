# Ch.10-B — SOC/SIEM Integration for ML Security Events

**AI Fortress** · Chapter 10: Monitoring, Drift Detection & SOC Integration

---

## What This Does

Normalises, triages, and routes ML security events into SOC/SIEM workflows:

- **Alert normaliser** — converts raw ML security events (drift alerts,
  auth failures, IP denies, rotation events) into CEF, LEEF, and JSON
  formats for ingestion by Splunk, QRadar, Microsoft Sentinel, and
  other SIEM platforms; maps severity to standard numeric levels
- **Alert triage classifier** — scores incoming alerts by severity,
  confidence, and attack-pattern indicators; applies rule-based triage
  to separate noise from actionable events; produces a triage decision
  with recommended analyst action
- **Escalation router** — routes triaged alerts to the correct response
  channel (Slack webhook stub, PagerDuty stub, email stub, ticket stub)
  based on severity, team ownership, and on-call schedules
- **Correlation engine** — detects multi-signal attack patterns by
  correlating alerts across a sliding time window; identifies composite
  attacks such as model extraction (many prediction + auth failures)
  and supply-chain compromise (drift + signing failure together)

---

## File Structure

```
soc-integration/
├── README.md
├── requirements.txt
├── alert_normaliser.py         # CEF / LEEF / JSON format conversion
├── alert_triage.py             # Rule-based triage classifier
├── escalation_router.py        # Severity-based channel routing
├── correlation_engine.py       # Multi-signal attack pattern detection
└── tests/
    └── test_soc_integration.py
```
