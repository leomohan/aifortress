# AI Fortress — Chapter 7 Code Resources
## Infrastructure as Code Security, Storage Hardening & Disaster Recovery

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Modo Bhaik  
**Chapter:** 7 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 7.A | `iac-security/` | Infrastructure-as-Code security scanning: Terraform and CloudFormation misconfiguration detection, policy-as-code enforcement, and drift detection between declared and deployed state |
| 7.B | `storage-hardening/` | ML artefact storage security: S3/GCS bucket policy auditor, encryption-at-rest verification, public access scanner, and object versioning + lifecycle rule enforcer |
| 7.C | `disaster-recovery/` | ML infrastructure disaster recovery: automated backup scheduler, recovery point objective (RPO) tracker, restoration verifier, and DR runbook generator |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 7)

1. Misconfigured infrastructure exposing ML pipelines to the internet
2. Publicly accessible model/dataset storage buckets
3. Unencrypted model weights or training data at rest
4. Infrastructure drift (manual changes overriding secure IaC definitions)
5. Missing object versioning enabling silent data destruction
6. Insufficient IAM permissions enabling privilege escalation
7. Lack of immutable audit trails for infrastructure changes
8. Single point of failure in ML pipeline infrastructure
9. Recovery time objective (RTO) breaches after incidents
10. Backup data stored without encryption or integrity verification

---

## Companion Site

**https://[your-domain]/resources/ch07**

---

*© AI Fortress · Modo Bhaik. For educational and professional use.*
