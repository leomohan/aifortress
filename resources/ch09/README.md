# AI Fortress — Chapter 9 Code Resources
## Network Security & Zero-Trust for ML Infrastructure

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 9 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 9.A | `api-gateway-security/` | ML API gateway hardening: JWT/API-key authentication, mTLS enforcement, request signing verification, IP allowlist/denylist, and structured security audit logging |
| 9.B | `service-mesh-zero-trust/` | Zero-trust service mesh controls: workload identity verifier, inter-service authorisation policy engine, lateral movement detector, and mTLS certificate validator |
| 9.C | `secrets-rotation/` | Automated secrets rotation: database credential rotator, API key lifecycle manager, certificate renewal tracker, and rotation audit trail |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 9)

1. Unauthenticated access to ML inference endpoints
2. API key leakage enabling model extraction or data theft
3. Man-in-the-middle attacks on model-serving traffic
4. Lateral movement from a compromised microservice to ML datastores
5. Overly permissive east-west traffic between ML pipeline components
6. Long-lived secrets that persist beyond their intended lifetime
7. Credential stuffing against inference APIs
8. Missing audit trail for who accessed what model when
9. Certificate expiry causing production outages
10. Rotation failures leaving stale credentials active post-compromise

---

## Companion Site

**https://[your-domain]/resources/ch09**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
