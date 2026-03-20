# AI Fortress — Chapter 11 Code Resources
## Identity & Access Management for ML Infrastructure

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 11 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 11.A | `iam-access-control/` | ML IAM core: RBAC engine with ML-specific roles, attribute-based policy evaluation, permission inheritance graph, and time-bound access with automatic expiry |
| 11.B | `pam-integration/` | Privileged Access Management for ML ops: just-in-time elevated access, session recording stubs, checkout/checkin of privileged credentials, and PAM audit trail |
| 11.C | `access-review-automation/` | Automated access review campaigns: stale entitlement detection, peer-group anomaly detection, review workflow engine, and access certification report |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 11)

1. Overly permissive service accounts with standing access to training data
2. Stale entitlements from former employees or rotated service accounts
3. Privilege escalation through role inheritance chains in ML pipelines
4. Insider threat via unmonitored privileged access to model artefacts
5. Standing privileged access to GPU clusters enabling silent exfiltration
6. Missing access reviews allowing entitlement drift over time
7. Peer-group anomaly — one user with far more permissions than colleagues
8. Credential sharing for convenience bypassing individual accountability

---

## Companion Site

**https://[your-domain]/resources/ch11**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
