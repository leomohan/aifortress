# Ch.08-B — ML Dependency Vulnerability Scanning

**AI Fortress** · Chapter 8: Software Supply Chain Security for ML

---

## What This Does

Scans ML project dependencies for security and compliance risks:

- **CVE scanner** — matches installed packages against a CVE database
  (NIST NVD JSON feed format); scores each finding by CVSS v3; applies
  an ML-context severity multiplier (training-time vs inference-time packages
  carry different risk profiles); produces a vulnerability report with
  fix-available flags
- **Licence checker** — classifies each package licence against a configurable
  policy (allowed, restricted, denied); flags copyleft licences (GPL, AGPL)
  that may require open-sourcing the ML model; detects licence ambiguity
  (NOASSERTION, UNKNOWN) and dual-licence packages
- **Transitive risk scorer** — builds a dependency graph and propagates risk
  scores from vulnerable leaf packages to their dependents; computes a
  composite risk score per package accounting for: direct CVE score,
  transitive exposure depth, and popularity (download count as proxy for
  exploit maturity)

---

## File Structure

```
dependency-scanning/
├── README.md
├── requirements.txt
├── cve_scanner.py              # CVE matching and CVSS scoring
├── licence_checker.py          # Licence policy compliance
├── transitive_risk_scorer.py   # Dependency graph risk propagation
└── tests/
    └── test_dependency_scanning.py
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
