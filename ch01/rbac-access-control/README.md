# Ch.01-B — RBAC Access Control for ML Data Pipelines

**AI Fortress** · Chapter 1: Data Confidentiality & Integrity

---

## What This Does

Role-Based + Attribute-Based Access Control for ML training data pipelines:

- **6 ML roles** — Data Engineer, ML Engineer, ML Researcher, Model Validator, Auditor, Admin — each with declared actions, resource prefixes, and a data-classification ceiling
- **Policy engine** — evaluates `(subject, role, action, resource, classification)` requests; four-step decision chain; returns a structured `AccessDecision`
- **Audit logger** — every permit/deny appended to an immutable JSON Lines file with full context
- **IAM generator** — translates role definitions to least-privilege AWS IAM policy JSON ready for `aws iam create-policy`
- **YAML config** — roles editable without code changes

## File Structure

```
rbac-access-control/
├── README.md
├── requirements.txt
├── roles.py              # Role dataclass + built-in definitions + YAML loader
├── policy_engine.py      # RBAC+ABAC evaluation + AuditLogger
├── iam_generator.py      # AWS IAM policy generator
├── config/
│   └── roles.yaml        # Editable role configuration
└── tests/
    └── test_policy_engine.py
```

## Quick Start

```python
from roles import load_roles
from policy_engine import PolicyEngine, AuditLogger

roles  = load_roles("config/roles.yaml")
engine = PolicyEngine(roles)
logger = AuditLogger("/var/log/aifortress/access.jsonl")

decision = engine.evaluate(
    subject        = "alice@example.com",
    role           = "ml-engineer",
    action         = "read",
    resource       = "s3://training-bucket/datasets/processed/train.parquet",
    classification = "CONFIDENTIAL",
)
logger.record(decision)

if not decision.permitted:
    raise PermissionError(decision.reason)
```

## Generate AWS IAM Policies

```bash
python iam_generator.py \
  --roles-config config/roles.yaml \
  --bucket my-training-bucket \
  --output-dir /tmp/iam-policies/

# Then deploy:
aws iam create-policy \
  --policy-name AIFortress-MLEngineer \
  --policy-document file:///tmp/iam-policies/ml-engineer.json
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
