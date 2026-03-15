# Ch.09-B — Service Mesh Zero-Trust Controls

**AI Fortress** · Chapter 9: Network Security & Zero-Trust for ML Infrastructure

---

## What This Does

Implements zero-trust controls for inter-service communication in ML
microservice architectures:

- **Workload identity verifier** — validates SPIFFE/X.509 SVIDs for
  service-to-service calls; checks SPIFFE ID against a trust domain
  allowlist; validates certificate chain, SANs, and not-expired; used as
  the identity anchor for all east-west authorisation decisions
- **Authorisation policy engine** — evaluates inter-service access requests
  against a declarative policy (source SPIFFE ID × destination service ×
  HTTP method × path); default-deny; supports wildcard path matching and
  method allowlists; structured deny log
- **Lateral movement detector** — detects anomalous east-west traffic patterns
  that may indicate a compromised ML service attempting lateral movement:
  unusual peer fan-out, access to unexpected datastores, high-frequency
  probing, and first-time connection to high-value services
- **mTLS certificate validator** — validates mTLS peer certificates for ML
  service connections: chain validation, SAN verification, expiry alerting
  (30/7/1 day thresholds), and revocation status stub

---

## File Structure

```
service-mesh-zero-trust/
├── README.md
├── requirements.txt
├── workload_identity_verifier.py   # SPIFFE/X.509 SVID validation
├── authz_policy_engine.py          # Declarative inter-service authz
├── lateral_movement_detector.py    # East-west anomaly detection
├── mtls_cert_validator.py          # mTLS peer certificate validation
└── tests/
    └── test_service_mesh.py
```
