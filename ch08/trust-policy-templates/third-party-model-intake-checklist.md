# AI Fortress — Third-Party Pretrained Model Intake Checklist
## Template · Chapter 8 · Resource 8.F

**Document ID:** `POLICY-SC-003`  
**Version:** 1.0  
**Purpose:** Security assessment checklist for every pretrained model sourced externally

---

## How to Use This Checklist

Complete this checklist before deploying any externally sourced pretrained model
(from HuggingFace, TF Hub, PyTorch Hub, or any other public or commercial registry).
All items in sections 1–4 are **mandatory**. Items in section 5 are recommended.

Attach the completed checklist, scan reports, and model card score to the
SBOM registry entry for this model.

---

## Section 1 — Source Verification

| # | Check | Result | Notes |
|---|-------|--------|-------|
| 1.1 | Model downloaded from the official source URL (not a mirror) | ☐ Pass / ☐ Fail | |
| 1.2 | Download URL is pinned to a specific commit SHA (not `main` or `latest`) | ☐ Pass / ☐ Fail | Commit: `_________________` |
| 1.3 | Publisher identity verified (organisation account, not anonymous) | ☐ Pass / ☐ Fail | Publisher: `_______________` |
| 1.4 | Model licence identified and recorded | ☐ Pass / ☐ Fail | Licence: `_________________` |
| 1.5 | Licence is ALLOWED or has legal sign-off (not DENIED) | ☐ Pass / ☐ Fail | |

---

## Section 2 — Integrity Verification

| # | Check | Result | Notes |
|---|-------|--------|-------|
| 2.1 | SHA-256 checksums obtained from the official source | ☐ Pass / ☐ Fail | |
| 2.2 | `weight_integrity_verifier.py` run — all shards PASS | ☐ Pass / ☐ Fail | Report attached: ☐ |
| 2.3 | All weight files accounted for (no MISSING or UNEXPECTED shards) | ☐ Pass / ☐ Fail | |
| 2.4 | Total model size matches published size | ☐ Pass / ☐ Fail | Published: `___` GB / Actual: `___` GB |

---

## Section 3 — Pickle Safety Scan

| # | Check | Result | Notes |
|---|-------|--------|-------|
| 3.1 | `pickle_safety_scanner.py` run on all `.pt` / `.pth` / `.pkl` files | ☐ Pass / ☐ Fail | |
| 3.2 | All files return verdict `SAFE` (no MALICIOUS or SUSPICIOUS) | ☐ Pass / ☐ Fail | Verdict: `_______________` |
| 3.3 | If SUSPICIOUS: security engineer reviewed the flagged opcodes | ☐ Pass / ☐ N/A | Reviewer: `______________` |
| 3.4 | Model converted to `safetensors` format if possible | ☐ Done / ☐ Not possible | |

---

## Section 4 — Model Card Completeness

| # | Check | Result | Notes |
|---|-------|--------|-------|
| 4.1 | `model_card_scorer.py` run — completeness score ≥ 70 | ☐ Pass / ☐ Fail | Score: `_____ / 100` |
| 4.2 | Model card includes training dataset name and licence | ☐ Pass / ☐ Fail | |
| 4.3 | Model card includes known limitations and out-of-scope uses | ☐ Pass / ☐ Fail | |
| 4.4 | Model card includes intended use case | ☐ Pass / ☐ Fail | |
| 4.5 | Mandatory fields present: name, version, licence, owner, intended_use, prohibited_use | ☐ Pass / ☐ Fail | |

---

## Section 5 — Recommended Checks

| # | Check | Result | Notes |
|---|-------|--------|-------|
| 5.1 | Model evaluated on internal benchmark — performance consistent with published metrics | ☐ Pass / ☐ Fail / ☐ N/A | |
| 5.2 | Backdoor / trojan detection run (activation clustering or spectral signature) | ☐ Pass / ☐ Fail / ☐ N/A | |
| 5.3 | Differential privacy budget documented | ☐ Done / ☐ N/A | ε = `_______` |
| 5.4 | Model registered in the SBOM registry with provenance metadata | ☐ Done | Registry ID: `___________` |
| 5.5 | Base model lineage recorded in SBOM (model card extension) | ☐ Done | |

---

## Decision

| Field | Value |
|-------|-------|
| **Intake Decision** | ☐ APPROVED for use  /  ☐ REJECTED  /  ☐ APPROVED with conditions |
| **Conditions / Restrictions** | |
| **Approved by** | |
| **Date** | |
| **Next review date** | |

---

## Attached Evidence

- [ ] Weight integrity report (`weight_integrity_report.json`)
- [ ] Pickle safety scan report
- [ ] Model card completeness score (`model_card_score.json`)
- [ ] SBOM entry (registry ID: `_________________`)
- [ ] Legal sign-off (if licence is RESTRICTED)
