# AI Fortress — Chapter 1 Code Resources
## Data Confidentiality & Integrity

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 1 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 1.A | `encryption-pipeline/` | AES-256-GCM streaming encryption with AWS KMS / Vault envelope key management |
| 1.B | `rbac-access-control/` | RBAC + ABAC policy engine with audit logging and AWS IAM policy generator |
| 1.C | `data-provenance-signing/` | Ed25519 provenance chain-of-custody signing and verification |

---

## Quick Setup (each resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

Each folder contains its own `README.md` with full usage instructions.

---

## Companion Site

Full documentation, updated library references, and resources for all  
17 chapters: **https://[your-domain]/resources**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
