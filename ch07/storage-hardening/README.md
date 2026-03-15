# Ch.07-B — ML Artefact Storage Hardening

**AI Fortress** · Chapter 7: Infrastructure Security, Storage & Disaster Recovery

---

## What This Does

Audits and enforces security controls on cloud object storage used for
ML artefacts (model checkpoints, datasets, training logs, experiment metadata):

- **Bucket policy auditor** — parses S3 and GCS bucket IAM policies, identifies
  overly permissive statements (public access, wildcard principals, missing
  condition keys), and scores each bucket against a hardening checklist
- **Encryption verifier** — verifies that server-side encryption is enabled and
  uses customer-managed keys (CMK); detects buckets using default AWS-managed
  keys (SSE-S3) when CMK is required by policy; checks KMS key rotation status
- **Public access scanner** — scans for public access vectors: ACL-based public
  access, bucket policy public statements, cross-account access without explicit
  allow-list, and presigned URL exposure windows exceeding policy limits
- **Lifecycle enforcer** — verifies that versioning and lifecycle rules are in
  place; generates a compliant lifecycle policy for ML artefact buckets with
  configurable retention tiers (hot/warm/cold/archive) and automatic noncurrent
  version expiration to limit storage cost and attack surface

---

## File Structure

```
storage-hardening/
├── README.md
├── requirements.txt
├── bucket_policy_auditor.py    # S3/GCS IAM policy analysis
├── encryption_verifier.py      # SSE and KMS key rotation checks
├── public_access_scanner.py    # Public access vector detection
├── lifecycle_enforcer.py       # Versioning + lifecycle rule enforcement
└── tests/
    └── test_storage_hardening.py
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
