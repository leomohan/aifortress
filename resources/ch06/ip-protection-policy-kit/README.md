# Ch.06-C — IP Protection Toolkit

**AI Fortress** · Chapter 6: Model Encryption, Signing & IP Protection

---

## What This Does

Comprehensive intellectual property protection for ML models and datasets:

- **Model fingerprinter** — generates a unique, stable fingerprint for a model
  based on its responses to a secret set of "fingerprint queries"; the
  fingerprint is robust to fine-tuning, quantisation, and output rounding;
  used to identify stolen models even when the attacker has modified the weights
- **Ownership verifier** — black-box ownership verification via API queries:
  given a suspect model API, the verifier sends the owner's fingerprint queries
  and measures agreement; returns a statistical confidence that the suspect
  model is derived from the owner's model
- **Dataset membership defence** — limits the information an adversary can
  extract from confidence scores to infer training set membership (complements
  Chapter 5 output sanitisation); implements differential privacy noise
  injection into confidence scores
- **Licence enforcer** — embeds a licence policy (allowed use scope, expiry,
  permitted deployments) into the model artefact and verifies at load time;
  raises LicenceViolationError if the deployment environment violates the policy

---

## File Structure

```
ip-protection-toolkit/
├── README.md
├── requirements.txt
├── model_fingerprinter.py      # Fingerprint generation and matching
├── ownership_verifier.py       # Black-box API ownership verification
├── membership_defence.py       # Confidence score DP noise + score rounding
├── licence_enforcer.py         # Licence policy embedding and enforcement
└── tests/
    └── test_ip_protection.py
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
