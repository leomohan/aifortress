# Ch.08-E — SBOM Governance & Policy Enforcement

**AI Fortress** · Chapter 8: Software Supply Chain Security for ML

---

## What This Does

Policy enforcement and registry management for SBOMs across the ML platform:

- **SBOM completeness scorer** — scores a CycloneDX SBOM against the
  AI Fortress completeness standard: all components must have PURL, version,
  and licence; components must be typed correctly; metadata must include
  timestamp, tool, and author; score 0–100 with configurable pass threshold
- **Licence policy gate** — enforces an organisation-wide licence policy
  against all components in an SBOM; raises LicencePolicyError if any denied
  or unknown licences are present; produces a policy compliance report
- **Blocklist checker** — checks all SBOM components against a known-bad
  component blocklist (typosquatted packages, known malicious packages, or
  internally prohibited components); raises BlocklistViolationError on match
- **SBOM registry** — a simple local SBOM registry (JSON file store) that
  tracks SBOM snapshots per project, supports baseline comparison for drift
  detection, and provides a query interface

---

## File Structure

```
sbom-governance/
├── README.md
├── requirements.txt
├── sbom_completeness_scorer.py   # SBOM field completeness scoring
├── licence_policy_gate.py        # Organisation licence policy enforcement
├── blocklist_checker.py          # Known-bad component detection
├── sbom_registry.py              # SBOM snapshot registry
└── tests/
    └── test_sbom_governance.py
```
