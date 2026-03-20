# Ch.07-A — Infrastructure-as-Code Security

**AI Fortress** · Chapter 7: Infrastructure Security, Storage & Disaster Recovery

---

## What This Does

Scans and enforces security policies on Infrastructure-as-Code definitions
for ML platforms, covering four controls:

- **Terraform scanner** — parses Terraform HCL (represented as JSON plan output)
  and flags misconfigurations relevant to ML infrastructure: open security groups
  (0.0.0.0/0 ingress), unencrypted EBS/EFS volumes, S3 buckets without
  versioning or logging, overly permissive IAM roles, public EC2 instances, and
  missing CloudTrail/GuardDuty for GPU training accounts
- **CloudFormation scanner** — parses CloudFormation templates (JSON/YAML) and
  applies the same ML-specific policy checks; also detects hardcoded credentials
  in Parameters/Mappings sections and missing DeletionPolicy on stateful resources
- **Policy-as-code enforcer** — defines security policy rules as dataclasses with
  severity (CRITICAL/HIGH/MEDIUM/LOW), auto-remediation hints, and links to
  compliance controls (CIS AWS, NIST 800-53, ISO 27001); emits a structured
  findings report with pass/fail gate
- **Drift detector** — compares a "golden" IaC state snapshot with the live
  deployed infrastructure state (provided as a describe-resources JSON dump);
  flags resources that exist in deployed but not in IaC (shadow IT), resources
  whose configuration differs (manual changes), and IaC resources not yet deployed

---

## File Structure

```
iac-security/
├── README.md
├── requirements.txt
├── terraform_scanner.py        # Terraform plan JSON misconfiguration scanner
├── cfn_scanner.py              # CloudFormation template security scanner
├── policy_enforcer.py          # Policy-as-code rule engine and findings report
├── drift_detector.py           # IaC vs deployed state drift detection
└── tests/
    └── test_iac_security.py
```

## Quick Start

```python
from terraform_scanner import TerraformScanner
from policy_enforcer import PolicyEnforcer

# Scan a Terraform plan JSON file
scanner  = TerraformScanner()
findings = scanner.scan_file("tfplan.json")

# Enforce policy gate (fails if any CRITICAL findings)
enforcer = PolicyEnforcer(fail_on_severity="CRITICAL")
enforcer.enforce(findings)   # raises PolicyViolationError if gate fails
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
