# AI Fortress — Supply Chain Security Policy
## Template · Chapter 8 · Resource 8.F

**Document ID:** `POLICY-SC-001`  
**Version:** 1.0  
**Classification:** Internal · Security  
**Review Cycle:** Annually or after any supply chain incident  

---

## 1. Purpose

This policy defines the minimum security requirements for all software
components, pretrained models, and infrastructure images used within the
ML platform. Its purpose is to prevent supply chain attacks that could
compromise model integrity, training data, or production inference systems.

---

## 2. Scope

This policy applies to:
- All Python packages and dependencies in ML training and serving environments
- All pretrained models sourced from external registries (HuggingFace, TF Hub, PyPI)
- All CI/CD pipeline components (GitHub Actions, container base images)
- All infrastructure-as-code modules and Terraform providers
- All team members who commit code, configure pipelines, or deploy ML models

---

## 3. Software Bill of Materials (SBOM)

| Requirement | Detail |
|-------------|--------|
| **SBOM format** | CycloneDX 1.4 JSON (mandatory) |
| **SBOM generation trigger** | Every build that produces a deployable artefact |
| **SBOM completeness score** | ≥ 75 / 100 (AI Fortress completeness standard) |
| **SBOM storage** | Committed to SBOM registry and attached to release artefact |
| **SBOM review** | Security team approval required before production promotion |
| **SBOM drift gate** | Added components must be on the approved allowlist |

---

## 4. Dependency Security Requirements

### 4.1 CVE Scanning

- All builds must pass CVE scanning before artefact promotion.
- **Gate:** Zero CRITICAL or HIGH findings (CVSS adjusted score ≥ 7.0).
- Training-time packages (torch, tensorflow, scikit-learn, etc.) apply a **×1.5 severity multiplier**.
- Fix deadline after first detection:
  - CRITICAL: **48 hours**
  - HIGH: **7 days**
  - MEDIUM: **30 days**

### 4.2 Licence Compliance

| Licence Category | Action Required |
|-----------------|-----------------|
| ALLOWED (MIT, Apache-2.0, BSD-*)  | No action |
| RESTRICTED (GPL-*, LGPL-3.0, MPL-2.0) | Legal sign-off before production deployment |
| DENIED (AGPL-3.0, SSPL-1.0, BUSL-1.1) | **Must not be used** — find alternative |
| UNKNOWN (NOASSERTION, blank) | **Blocks promotion** — must be resolved |

### 4.3 Blocklist Enforcement

- All components are checked against the ML supply chain threat blocklist on every build.
- Zero blocklist hits are permitted in any production artefact.
- Blocklist is reviewed and updated monthly by the Security team.

---

## 5. Pretrained Model Security Requirements

| Control | Requirement |
|---------|-------------|
| **Pickle safety scan** | All `.pt`, `.pth`, `.pkl` files must pass pickle safety scan before loading |
| **Weight integrity** | SHA-256 checksums must be verified against a signed manifest |
| **Model card score** | ≥ 70 / 100 on the AI Fortress model card completeness standard |
| **Source registry** | Models sourced from HuggingFace must be pinned to a specific commit SHA |
| **Provenance** | Model card must reference training dataset lineage |

---

## 6. CI/CD Pipeline Hardening

| Control | Requirement |
|---------|-------------|
| **Action pinning** | All GitHub Actions `uses:` references must be pinned to a full 40-character SHA1 |
| **SLSA provenance** | All model and dataset artefacts must have SLSA v0.2 provenance attestation |
| **Build attestation** | All training jobs must capture a `BuildAttestation` JSON |
| **Artefact signing** | All deployable artefacts must be signed with Ed25519 |
| **Secrets in env** | Secrets must not be captured in build attestations or provenance |

---

## 7. Infrastructure-as-Code Security

| Control | Requirement |
|---------|-------------|
| **IaC scanning** | All Terraform and CloudFormation changes must pass the AI Fortress IaC scanner |
| **Policy gate** | Zero CRITICAL findings, zero HIGH findings before `terraform apply` |
| **Drift detection** | IaC drift checks must run daily in CI; SHADOW resources must be remediated within 24h |

---

## 8. Exception Process

Exceptions to this policy require:
1. Written justification from the requesting team
2. Security team review and written sign-off
3. Time-bounded exception (maximum 30 days)
4. Compensating control documented in the exception record

---

## 9. Enforcement

Violations are detected automatically by CI/CD gates. Pipeline failures block
promotion to production. Repeated violations are escalated to the Security
team and recorded in the risk register.

---

## 10. Document Control

| Field | Value |
|-------|-------|
| Author | [OWNER] |
| Approved by | [APPROVER] |
| Approval date | [DATE] |
| Next review | [DATE + 12 months] |
