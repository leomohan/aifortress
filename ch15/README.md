# AI Fortress — Chapter 15 Code Resources
## Edge AI & Embedded ML Security

**Book:** AI Fortress: 17 Pillars for Securing the Machine Learning Lifecycle  
**Author:** Mohan Krishnamurthy  
**Chapter:** 15 of 17

---

## Resources in This Package

| ID | Folder | Type | Description |
|----|--------|------|-------------|
| 15.A | `hrot-integration/` | Code | Hardware Root of Trust integration: TPM 2.0 attestation client, secure boot log verifier, platform integrity checker |
| 15.B | `encrypted-model-trustzone/` | Code | ARM TrustZone model protection: model encryption wrapper, secure enclave loader simulator, memory isolation verifier |
| 15.C | `secure-ota-pipeline/` | Code | Secure OTA firmware/model updates: signed update package builder, update verifier, rollback guard |
| 15.D | `secure-provisioning/` | Code | Device provisioning security: device identity issuer, certificate chain verifier, attestation token validator |
| 15.E | `physical-adversarial-eval/` | Code | Physical adversarial robustness evaluation: patch robustness tester, environmental distortion simulator, robustness score reporter |
| 15.F | `edge-threat-model-templates/` | Templates | STRIDE threat model for edge AI devices, attack surface matrix, and hardware security checklist |

---

## Quick Setup (each code resource)

```bash
cd <resource-folder>
pip install -r requirements.txt
pytest tests/ -v
```

---

## Threat Taxonomy Covered (Chapter 15)

1. Physical tampering — adversary opens device and extracts model weights from flash
2. Cold-boot / side-channel — key material extracted from DRAM after power cycle
3. Insecure boot — unsigned firmware replaced at factory or in transit
4. OTA interception — model update intercepted and replaced mid-transit
5. Rollback via OTA — attacker downgrades firmware to known-vulnerable version
6. Missing device identity — clone devices injected into deployment fleet
7. Physical adversarial patches — printed patterns fool CV models at inference time
8. Environmental degradation — dust, glare, occlusion degrade edge model accuracy
9. Unattested execution — model runs on unverified hardware/firmware stack
10. Side-channel leakage — power/EM traces reveal model structure or private inputs

---

## Companion Site

**https://[your-domain]/resources/ch15**

---

*© AI Fortress · Mohan Krishnamurthy. For educational and professional use.*
