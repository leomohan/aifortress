# AI Fortress — Chapter 10 Code Resources
## Monitoring, Drift Detection & SOC Integration

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 10 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 10.A | `drift-detection-dashboard/` | ML model and data drift detection: statistical drift tests (KS, PSI, chi-squared), prediction drift monitoring, feature importance drift, and a structured drift report with pass/fail gates |
| 10.B | `soc-integration/` | SOC/SIEM integration for ML security events: alert normalisation to CEF/LEEF/JSON formats, alert triage classifier, escalation router, and correlation engine for multi-signal ML attacks |
| 10.C | `monitoring-stack/` | Production ML monitoring stack: health check framework, metric collector with Prometheus exposition format, SLO tracker with error-budget burn rate, and anomaly-based alerting rules |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 10)

1. Silent model degradation caused by production data drift
2. Adversarial input campaigns detectable only via aggregate statistics
3. Model poisoning detectable through prediction distribution shift
4. Security events buried in operational noise without normalisation
5. Slow-burn attacks missed by single-signal alerting
6. SLO violations masking security incidents (availability as cover)
7. Feature importance inversion indicating feature-level attacks
8. Missing observability enabling dwell time extension

---

## Companion Site

**https://[your-domain]/resources/ch10**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
