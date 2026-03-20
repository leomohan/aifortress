# AI Fortress — Chapter 8 Code Resources
## Software Supply Chain Security for ML

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 8 of 17

---

## Resources in This Package

| ID | Folder | Description |
|----|--------|-------------|
| 8.A | `sbom-pipeline/` | Software Bill of Materials generation for ML projects: Python environment SBOM (CycloneDX/SPDX), model card SBOM extension, and SBOM diff/change detection |
| 8.B | `dependency-scanning/` | ML dependency vulnerability scanning: CVE matching against pip/conda environments, licence compliance checking, and transitive dependency risk scoring |
| 8.C | `pretrained-model-assessment/` | Security assessment of pretrained models from public registries: pickle safety scanning, weight integrity verification, and model card completeness scoring |
| 8.D | `cicd-hardening-slsa/` | CI/CD pipeline hardening for SLSA Level 2/3: provenance generation, pinned action verification, build environment attestation, and artefact signing |
| 8.E | `sbom-governance/` | SBOM governance and policy enforcement: SBOM completeness scoring, licence policy gate, known-bad component blocklist, and SBOM registry |
| 8.F | `trust-policy-templates/` | Ready-to-use trust policy templates: supply chain security policy, SBOM acceptance criteria, third-party model intake checklist |

---

## Quick Setup (each code resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 8)

1. Malicious packages injected into ML training environments
2. Vulnerable dependencies with known CVEs in model serving stacks
3. Trojanised pretrained models from public registries (HuggingFace, TF Hub)
4. Pickle-based code execution via model checkpoint loading
5. Dependency confusion attacks (internal package name squatting)
6. Licence compliance violations introducing legal IP risk
7. CI/CD pipeline compromise enabling artefact tampering
8. Missing SLSA provenance enabling undetected build tampering
9. Transitive dependency risk (vulnerable indirect dependencies)
10. SBOM drift (environment changing without SBOM update)

---

## Companion Site

**https://[your-domain]/resources/ch08**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
