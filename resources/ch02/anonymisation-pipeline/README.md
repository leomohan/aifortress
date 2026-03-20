# Ch.02-B — PII Detection & Anonymisation Pipeline

**AI Fortress** · Chapter 2: Data Privacy & Compliance

---

## What This Does

Automated PII detection and anonymisation pipeline for ML training datasets:

- **PII detector** — regex + rule-based detection of 12 PII types (email, phone, SSN, credit card, IP address, NHS/NPI numbers, names, DOB, postcodes, passport numbers, bank accounts, biometric references)
- **k-anonymity enforcer** — verifies that every combination of quasi-identifiers (age band, gender, postcode prefix) appears at least *k* times; generalises or suppresses to meet the threshold
- **l-diversity enforcer** — extends k-anonymity to require at least *l* distinct sensitive-attribute values per equivalence class, preventing homogeneity attacks
- **Pseudonymisation** — deterministic HMAC-SHA256 tokenisation with a secret key; same input always maps to the same token (referential integrity preserved); tokens are irreversible without the key
- **Format-preserving tokenisation** — replaces PII with realistic-looking synthetic values (email → fake email, phone → fake phone) for testing datasets that must pass format validation
- **Anonymisation report** — records what was detected, what transformation was applied, and the resulting k/l values for audit evidence

---

## File Structure

```
anonymisation-pipeline/
├── README.md
├── requirements.txt
├── pii_detector.py           # 12-type PII detection engine
├── k_anonymity.py            # k-anonymity and l-diversity enforcement
├── pseudonymiser.py          # HMAC-SHA256 deterministic pseudonymisation
├── format_preserving.py      # Format-preserving fake-value substitution
├── anonymisation_report.py   # Audit report generator
└── tests/
    └── test_anonymisation.py
```

## Quick Start

```python
from pii_detector import PIIDetector
from pseudonymiser import Pseudonymiser

detector = PIIDetector()
findings = detector.scan_dataframe(df, columns=["notes", "email", "phone"])
print(findings.summary())

pseud = Pseudonymiser(secret_key=b"your-32-byte-secret-key-here---x")
df["email"] = df["email"].apply(pseud.pseudonymise)
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
