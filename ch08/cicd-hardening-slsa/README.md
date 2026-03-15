# Ch.08-D — CI/CD Hardening & SLSA Provenance

**AI Fortress** · Chapter 8: Software Supply Chain Security for ML

---

## What This Does

Hardens CI/CD pipelines for ML projects toward SLSA Level 2/3:

- **Provenance generator** — generates SLSA v0.2 provenance attestations for
  ML build artefacts: records the source repo, commit SHA, build trigger,
  builder identity, build parameters, and output artefact digests in a
  signed in-toto statement
- **Pinned action verifier** — scans GitHub Actions workflow YAML files and
  flags any `uses:` reference not pinned to a full SHA1 commit hash; mutable
  tags (v1, v2, main, latest) are flagged as supply chain risks
- **Build attestation** — captures the complete build environment state
  (OS, Python version, installed packages, environment variables filtered for
  secrets, git state) and produces a signed BuildAttestation JSON
- **Artefact signer** — signs build output artefacts with Ed25519 and produces
  a detached signature + cosign-compatible bundle for registry upload

---

## File Structure

```
cicd-hardening-slsa/
├── README.md
├── requirements.txt
├── provenance_generator.py     # SLSA v0.2 provenance attestation
├── pinned_action_verifier.py   # GitHub Actions SHA pin verification
├── build_attestation.py        # Build environment capture and attestation
├── artefact_signer.py          # Ed25519 artefact signing for CI outputs
└── tests/
    └── test_cicd_hardening.py
```
