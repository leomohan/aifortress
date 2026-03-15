# AI Fortress — SBOM Acceptance Criteria
## Template · Chapter 8 · Resource 8.F

**Document ID:** `POLICY-SC-002`  
**Version:** 1.0  
**Purpose:** Define what constitutes an acceptable SBOM for production artefact promotion

---

## Automated Gate Criteria (CI/CD enforced)

All of the following must pass before a build artefact is promoted to production.

### G1 — SBOM Present

- [ ] An SBOM in CycloneDX 1.4 JSON format is attached to the build artefact.
- [ ] The SBOM `serialNumber` is unique and recorded in the SBOM registry.
- [ ] The SBOM `metadata.timestamp` is within 24 hours of the build.

### G2 — SBOM Completeness Score ≥ 75

- [ ] `sbom_completeness_scorer.py` returns `overall_pass = True`.
- [ ] All components have a `purl` (Package URL).
- [ ] All components have an explicit `version` (not `UNKNOWN`).
- [ ] ≥ 60 % of components have a `licenses` entry.
- [ ] All components have a valid CycloneDX `type`.

### G3 — CVE Scan Passed

- [ ] Zero CRITICAL CVE findings (adjusted CVSS ≥ 9.0).
- [ ] Zero HIGH CVE findings (adjusted CVSS ≥ 7.0).
- [ ] CVE scan report is attached to the build artefact.
- [ ] Training-time packages use the ×1.5 ML-context multiplier.

### G4 — Licence Policy Passed

- [ ] Zero DENIED licence findings.
- [ ] Zero UNKNOWN licence findings.
- [ ] RESTRICTED licences have a recorded legal sign-off (see exception register).

### G5 — Blocklist Clean

- [ ] Zero blocklist hits for any component.
- [ ] Blocklist database used was updated within the last 7 days.

### G6 — SBOM Drift within Policy

- [ ] Any components added since the last approved SBOM are on the allowlist.
- [ ] No unapproved components were added.
- [ ] Licence changes are flagged for review.

---

## Manual Review Criteria (Security team sign-off)

The following require human review before production promotion:

| Criteria | Reviewer |
|----------|----------|
| Any new ML framework added (torch, tensorflow, jax, etc.) | ML Security Lead |
| Any RESTRICTED licence in the SBOM | Legal / Security |
| Any model weight files added or replaced | ML Security Lead |
| SBOM completeness score 60–74 (borderline) | Security team |
| Any exception to G1–G6 | Security team + CISO |

---

## Rejection Criteria (automatic block, no exceptions without CISO sign-off)

A build is automatically rejected if:
- Any DENIED licence is present (AGPL-3.0, SSPL-1.0, BUSL-1.1, etc.)
- Any blocklisted component is present
- Any CRITICAL CVE (adjusted) is unpatched
- Pickle safety scan returns `MALICIOUS` verdict on any model file
- Weight integrity check fails for any model shard
- SLSA provenance is missing from the artefact bundle

---

## Acceptance Record Template

```
SBOM Acceptance Record
======================
Project:          [name]
Version:          [version]
Build ID:         [uuid]
SBOM Serial:      [urn:uuid:...]
Date:             [YYYY-MM-DD]

Gate Results:
  G1 SBOM Present:           PASS / FAIL
  G2 Completeness (score):   PASS / FAIL  ([score]/100)
  G3 CVE Scan:               PASS / FAIL  ([C]C [H]H [M]M [L]L)
  G4 Licence Policy:         PASS / FAIL
  G5 Blocklist:              PASS / FAIL
  G6 SBOM Drift:             PASS / FAIL

Overall:          APPROVED / REJECTED

Approved by:      [name]
Approval date:    [YYYY-MM-DD]
Notes:            [any exceptions or observations]
```
