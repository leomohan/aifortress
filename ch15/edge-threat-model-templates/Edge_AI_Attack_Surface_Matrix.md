# Edge AI Attack Surface Matrix
## AI Fortress — Chapter 15 Template 15.F-2

**Purpose:** Map all attack surfaces of an edge AI device to relevant
attack vectors, existing controls, and residual risk.  
**Use alongside:** STRIDE Threat Model (15.F-1) and Hardware Security Checklist (15.F-3).

---

## Attack Surface Inventory

Rate each surface: **Exposure** = how accessible to an attacker (1=isolated, 5=internet-facing).
**Impact** = consequence of successful attack. **Risk** = E × I.

---

### 1. Physical Attack Surface

| Surface | Vector | Exposure | Impact | Risk | Control | Residual Risk |
|---------|--------|----------|--------|------|---------|--------------|
| Device enclosure | Physical opening, PCB probing | | | | Tamper-evident seals, epoxy potting | |
| JTAG/SWD debug port | Direct code execution, key extraction | | | | Fuse/disable in production | |
| UART console | Bootloader access, shell | | | | Disable UART in production image | |
| USB port | Firmware injection, data exfiltration | | | | Disable unused USB, USB allowlist | |
| SD/eMMC slot | Filesystem replacement, model swap | | | | Encrypt storage, verify boot | |
| Power rails | Power analysis (SPA/DPA) | | | | Noise injection, metal shielding | |
| EM emissions | Electromagnetic side-channel | | | | EM shielding, masking | |
| Optical sensor | Adversarial patches, laser glare | | | | Adversarial training, patch detection | |

---

### 2. Firmware & Boot Attack Surface

| Surface | Vector | Exposure | Impact | Risk | Control | Residual Risk |
|---------|--------|----------|--------|------|---------|--------------|
| Boot ROM | Immutable root of trust compromise | | | | ROM fuse, hardware secure boot | |
| Bootloader (stage 1/2) | Unsigned bootloader replacement | | | | Signature chain, measured boot | |
| OS kernel | Kernel exploit, privilege escalation | | | | Minimal OS, mandatory access control | |
| Device driver | Driver exploit via peripheral | | | | Driver signing, kernel lockdown | |
| OTA update receiver | Malicious package injection | | | | Signed packages, HMAC-SHA256, TLS | |
| Rollback via OTA | Downgrade to vulnerable version | | | | Anti-rollback counter (eFuse/TPM NV) | |

---

### 3. Network Attack Surface

| Surface | Vector | Exposure | Impact | Risk | Control | Residual Risk |
|---------|--------|----------|--------|------|---------|--------------|
| OTA HTTPS endpoint | MITM, server spoofing | | | | Certificate pinning, mTLS | |
| REST/gRPC inference API | Input manipulation, DoS | | | | Input validation, rate limiting | |
| MQTT / CoAP telemetry | Message injection, replay | | | | Token auth, sequence numbers | |
| Wi-Fi / BLE | Deauth, probe, man-in-the-middle | | | | WPA3, BLE pairing security | |
| DNS resolution | DNS hijack, redirect to rogue OTA | | | | DNSSEC, DoT/DoH, pinned IPs | |
| mDNS / SSDP discovery | Device enumeration | | | | Disable if not needed | |

---

### 4. ML Model Attack Surface

| Surface | Vector | Exposure | Impact | Risk | Control | Residual Risk |
|---------|--------|----------|--------|------|---------|--------------|
| Model weights at rest | Extraction from flash/eMMC | | | | AES-256-GCM encryption, TPM key | |
| Model weights in RAM | Cold-boot attack, DMA attack | | | | DRAM encryption, TrustZone isolation | |
| Inference API inputs | Adversarial examples, evasion | | | | Adversarial training, input preprocessing | |
| Model outputs / confidence | Membership inference, model inversion | | | | Output perturbation, confidence suppression | |
| Model update distribution | Trojanised model via OTA | | | | Model signing, hash verification, canary auditing | |
| Federated gradient exchange | Gradient poisoning | | | | Gradient clipping, Byzantine-robust aggregation | |

---

### 5. Supply Chain Attack Surface

| Surface | Vector | Exposure | Impact | Risk | Control | Residual Risk |
|---------|--------|----------|--------|------|---------|--------------|
| Hardware supply (PCB, chips) | Counterfeit components, hardware trojans | | | | Trusted supplier program, hardware inspection | |
| Pre-trained model (third-party) | Backdoor / trojan in downloaded weights | | | | Model provenance check, activation analysis | |
| OS / container base image | Compromised base layer | | | | SBOM, image signing, vulnerability scanning | |
| Python / C++ dependencies | Dependency confusion, typosquat | | | | Lock files, private registry, hash pinning | |
| Factory provisioning environment | Rogue CA, key leakage at factory | | | | HSM-backed provisioning, factory security audit | |
| CI/CD pipeline | Build artefact replacement | | | | Signed builds, SLSA Level 2+, Chapter 8 controls | |

---

## Aggregate Risk Summary

Complete after filling in all surfaces above.

| Category | High-Risk Surfaces (Risk ≥ 15) | Mitigated? |
|----------|---------------------------------|-----------|
| Physical | | ☐ Yes ☐ No ☐ Partial |
| Firmware & Boot | | ☐ Yes ☐ No ☐ Partial |
| Network | | ☐ Yes ☐ No ☐ Partial |
| ML Model | | ☐ Yes ☐ No ☐ Partial |
| Supply Chain | | ☐ Yes ☐ No ☐ Partial |

---

## Remediation Tracker

| Surface ID | Risk Score | Owner | Fix By | Status |
|------------|-----------|-------|--------|--------|
| | | | | ☐ Open ☐ In Progress ☐ Done |
| | | | | ☐ Open ☐ In Progress ☐ Done |

---

*Template: AI Fortress Chapter 15 · Mohan Krishnamurthy*
