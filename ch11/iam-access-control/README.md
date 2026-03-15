# Ch.11-A — ML IAM Access Control

**AI Fortress** · Chapter 11: Identity & Access Management for ML Infrastructure

---

## What This Does

Implements a complete IAM engine tailored to ML infrastructure access patterns:

- **RBAC engine** — ML-specific role hierarchy (data-scientist, ml-engineer,
  model-reviewer, mlops-admin, auditor); role assignment with optional expiry;
  permission resolution via role inheritance; permission check returns an
  `AccessDecision` with full audit trail; built-in ML permission catalogue
  covering model read/write/deploy, training data access, pipeline execution,
  registry management, and infrastructure control
- **ABAC policy evaluator** — attribute-based access control policies evaluated
  at request time; policy conditions match on subject attributes (team, clearance,
  location), resource attributes (classification, owner, environment), and
  context attributes (time-of-day, request IP, MFA status); DENY overrides ALLOW;
  policies loaded from JSON
- **Permission inheritance graph** — directed acyclic graph of role relationships;
  detects inheritance cycles; resolves effective permissions for any role including
  all ancestor roles; identifies over-privileged inheritance paths
- **Time-bound access** — access grants with configurable TTL and automatic
  expiry; expiry check on every access decision; scheduled clean-up of expired
  grants; near-expiry notification list

---

## File Structure

```
iam-access-control/
├── README.md
├── requirements.txt
├── rbac_engine.py              # Role-based access control with ML roles
├── abac_policy_evaluator.py    # Attribute-based policy evaluation
├── permission_graph.py         # Role inheritance DAG and cycle detection
├── time_bound_access.py        # TTL-based access grants with expiry
└── tests/
    └── test_iam.py
```
