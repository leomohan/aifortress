# STRIDE Threat Model — Edge AI Device
## AI Fortress — Chapter 15 Template 15.F-1

**Standard:** STRIDE (Microsoft) + MITRE ATT&CK for ICS  
**Scope:** Embedded ML inference device (camera, sensor node, gateway)  
**Version:** 1.0

---

## System Description

| Field | Value |
|-------|-------|
| **Device Name / Model** | |
| **Device Class** | ☐ Camera ☐ Sensor Node ☐ Edge Gateway ☐ Robotics Controller ☐ Other: |
| **ML Task** | ☐ Image Classification ☐ Object Detection ☐ Anomaly Detection ☐ Speech ☐ Other: |
| **Connectivity** | ☐ Wi-Fi ☐ LTE/5G ☐ Ethernet ☐ BLE ☐ Isolated |
| **Deployment Environment** | ☐ Indoor ☐ Outdoor ☐ Industrial ☐ Healthcare ☐ Public Space |
| **Assessed By** | |
| **Date** | |

---

## Data Flow Diagram Reference

```
[Cloud Backend] ←─OTA Update─→ [Edge Gateway] ←─Inference Request─→ [Sensor/Camera]
      ↑                               ↑                                      ↑
      │ Model Registry                │ Secure Boot                          │ Physical Access
      │ Attestation Service           │ TrustZone TEE                        │ Environmental Inputs
      └───────────────────────────────┘                                      └──────────────────
```

*(Replace with actual DFD for your system)*

---

## STRIDE Threat Analysis

For each threat category, identify threats relevant to your edge AI system.
Rate likelihood (1–5) and impact (1–5). Risk = L × I.

---

### S — Spoofing

| # | Threat | Component | L | I | Risk | Mitigation | Status |
|---|--------|-----------|---|---|------|-----------|--------|
| S-01 | Clone device injects fake telemetry | Device Identity | | | | Device certificates, TPM-bound keys | ☐ Open ☐ Mitigated |
| S-02 | Adversary spoofs OTA server | OTA Client | | | | Certificate pinning, domain validation | ☐ Open ☐ Mitigated |
| S-03 | Fake attestation report sent to backend | Attestation | | | | TPM-signed quotes, nonce binding | ☐ Open ☐ Mitigated |
| S-04 | Impersonation of provisioning service | Provisioning | | | | Mutual TLS, token binding | ☐ Open ☐ Mitigated |
| S-05 | | | | | | | |

---

### T — Tampering

| # | Threat | Component | L | I | Risk | Mitigation | Status |
|---|--------|-----------|---|---|------|-----------|--------|
| T-01 | Model weights replaced on flash storage | Model Storage | | | | Model encryption (AES-GCM), hash check | ☐ Open ☐ Mitigated |
| T-02 | Firmware replaced via JTAG/UART | Boot ROM | | | | Secure Boot, signed firmware, JTAG fuse | ☐ Open ☐ Mitigated |
| T-03 | OTA package modified in transit | OTA Transport | | | | TLS + HMAC-SHA256 package signature | ☐ Open ☐ Mitigated |
| T-04 | PCR values manipulated before attestation | TPM | | | | TPM-sealed PCR quotes, replay prevention | ☐ Open ☐ Mitigated |
| T-05 | Adversarial patch applied to camera feed | Sensor Input | | | | Patch detection, adversarial training | ☐ Open ☐ Mitigated |
| T-06 | Shared memory written by Normal World | TrustZone | | | | TZASC isolation, memory bounds checking | ☐ Open ☐ Mitigated |
| T-07 | | | | | | | |

---

### R — Repudiation

| # | Threat | Component | L | I | Risk | Mitigation | Status |
|---|--------|-----------|---|---|------|-----------|--------|
| R-01 | Device denies receiving OTA update | OTA Log | | | | Signed OTA receipt, append-only log | ☐ Open ☐ Mitigated |
| R-02 | Operator denies approving rollback | Rollback Log | | | | Hash-chained audit trail | ☐ Open ☐ Mitigated |
| R-03 | | | | | | | |

---

### I — Information Disclosure

| # | Threat | Component | L | I | Risk | Mitigation | Status |
|---|--------|-----------|---|---|------|-----------|--------|
| I-01 | Model weights extracted from flash | Flash Storage | | | | AES-256 encryption, TPM-bound key | ☐ Open ☐ Mitigated |
| I-02 | Weights leaked via side-channel (power/EM) | CPU/Memory | | | | Masking, noise injection, metal shielding | ☐ Open ☐ Mitigated |
| I-03 | Inference input reconstructed (model inversion) | Model API | | | | Output perturbation, confidence suppression | ☐ Open ☐ Mitigated |
| I-04 | Cold-boot attack extracts key material from DRAM | Memory | | | | DRAM encryption, memory scrambling | ☐ Open ☐ Mitigated |
| I-05 | Debug UART exposes boot log and keys | UART/JTAG | | | | Fuse JTAG, disable debug in production | ☐ Open ☐ Mitigated |
| I-06 | | | | | | | |

---

### D — Denial of Service

| # | Threat | Component | L | I | Risk | Mitigation | Status |
|---|--------|-----------|---|---|------|-----------|--------|
| D-01 | Malicious OTA bricks device | OTA Updater | | | | Dual-partition A/B, rollback on fail | ☐ Open ☐ Mitigated |
| D-02 | Adversarial input causes model crash / OOM | Inference Engine | | | | Input validation, memory limits, watchdog | ☐ Open ☐ Mitigated |
| D-03 | Sensor flooding / excessive inference requests | API Layer | | | | Rate limiting, request queuing | ☐ Open ☐ Mitigated |
| D-04 | | | | | | | |

---

### E — Elevation of Privilege

| # | Threat | Component | L | I | Risk | Mitigation | Status |
|---|--------|-----------|---|---|------|-----------|--------|
| E-01 | Normal World code escapes to Secure World | TrustZone | | | | TEE isolation, TA validation, fuzzing | ☐ Open ☐ Mitigated |
| E-02 | Compromised TA gains full TEE control | TEE | | | | TA signing, OP-TEE hardening | ☐ Open ☐ Mitigated |
| E-03 | OTA daemon runs as root unnecessarily | OS | | | | Principle of least privilege, namespaces | ☐ Open ☐ Mitigated |
| E-04 | | | | | | | |

---

## Risk Summary

| Risk Level | Count | Threshold Action |
|------------|-------|-----------------|
| Critical (20–25) | | Must fix before deployment |
| High (10–19) | | Fix before deployment or accept with CISO sign-off |
| Medium (5–9) | | Plan remediation within 90 days |
| Low (1–4) | | Track; remediate in next release cycle |

---

## Out-of-Scope

Document what is explicitly excluded:

| Excluded | Reason |
|----------|--------|
| Cloud backend security | Covered by Chapter 9 (Zero-Trust) |
| Training pipeline security | Covered by Chapter 4 |
| Physical facility security | Physical security team scope |

---

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Security Architect | | |
| Hardware Engineer | | |
| ML Engineer | | |
| Product Owner | | |

---

*Template: AI Fortress Chapter 15 · Modo Bhaik*
