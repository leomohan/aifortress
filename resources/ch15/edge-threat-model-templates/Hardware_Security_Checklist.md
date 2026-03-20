# Hardware Security Checklist — Edge AI Device
## AI Fortress — Chapter 15 Template 15.F-3

**Purpose:** Pre-deployment hardware security verification for edge AI devices.  
**When to use:** Before factory sign-off, before field deployment, and at periodic security reviews.

---

## Section 1: Secure Boot

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 1.1 | Secure Boot is enabled and enforced on target hardware | ☐ | ☐ | ☐ | |
| 1.2 | Boot ROM is read-only after provisioning (fuse blown) | ☐ | ☐ | ☐ | |
| 1.3 | All boot stages (BL1, BL2, OS) are signed by trusted key | ☐ | ☐ | ☐ | |
| 1.4 | Signature verification failures halt the boot process | ☐ | ☐ | ☐ | |
| 1.5 | Measured boot / TCG Event Log is enabled | ☐ | ☐ | ☐ | |
| 1.6 | PCR values are attested remotely before device is activated | ☐ | ☐ | ☐ | |
| 1.7 | A/B partition scheme is implemented for safe OTA recovery | ☐ | ☐ | ☐ | |

---

## Section 2: Key Management & Cryptography

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 2.1 | Device identity key is generated on-device (never exported) | ☐ | ☐ | ☐ | |
| 2.2 | Keys are stored in TPM 2.0, eFuse, or secure enclave | ☐ | ☐ | ☐ | |
| 2.3 | AES-256 (or equivalent) used for storage encryption | ☐ | ☐ | ☐ | |
| 2.4 | TLS 1.3 (minimum TLS 1.2) used for all network comms | ☐ | ☐ | ☐ | |
| 2.5 | Certificate revocation (CRL / OCSP) is supported | ☐ | ☐ | ☐ | |
| 2.6 | OTA packages are HMAC-SHA256 signed before transmission | ☐ | ☐ | ☐ | |
| 2.7 | Anti-rollback counter stored in write-once NV storage | ☐ | ☐ | ☐ | |
| 2.8 | No hardcoded credentials in firmware or model artefacts | ☐ | ☐ | ☐ | |

---

## Section 3: TrustZone / TEE (if applicable)

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 3.1 | ARM TrustZone (or equivalent TEE) is enabled | ☐ | ☐ | ☐ | |
| 3.2 | TZASC is configured; no overlap between secure/normal regions | ☐ | ☐ | ☐ | |
| 3.3 | Model weights are loaded and executed only in Secure World | ☐ | ☐ | ☐ | |
| 3.4 | Trusted Applications (TAs) are signed before loading | ☐ | ☐ | ☐ | |
| 3.5 | Normal World cannot map or execute Secure World memory | ☐ | ☐ | ☐ | |
| 3.6 | Shared memory buffers have strict size/type validation | ☐ | ☐ | ☐ | |

---

## Section 4: Debug & Physical Interface Hardening

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 4.1 | JTAG/SWD debug interface is disabled (fused off) | ☐ | ☐ | ☐ | |
| 4.2 | UART debug console is disabled in production image | ☐ | ☐ | ☐ | |
| 4.3 | Unused USB ports are disabled in firmware | ☐ | ☐ | ☐ | |
| 4.4 | Test pads on PCB are removed or covered in production | ☐ | ☐ | ☐ | |
| 4.5 | Enclosure uses tamper-evident seals or epoxy potting | ☐ | ☐ | ☐ | |
| 4.6 | SD card slot is absent or enforces verified boot media | ☐ | ☐ | ☐ | |

---

## Section 5: OTA Update Security

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 5.1 | OTA server certificate is pinned on device | ☐ | ☐ | ☐ | |
| 5.2 | OTA packages are verified before writing to flash | ☐ | ☐ | ☐ | |
| 5.3 | Rollback to older version is blocked by hardware counter | ☐ | ☐ | ☐ | |
| 5.4 | Failed OTA automatically reverts to previous partition | ☐ | ☐ | ☐ | |
| 5.5 | OTA events are logged to append-only audit trail | ☐ | ☐ | ☐ | |
| 5.6 | Emergency rollback requires dual-authorisation | ☐ | ☐ | ☐ | |

---

## Section 6: ML Model Security

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 6.1 | Model weights are AES-256 encrypted at rest | ☐ | ☐ | ☐ | |
| 6.2 | Model hash is verified before loading | ☐ | ☐ | ☐ | |
| 6.3 | Model inference runs inside TEE (if available) | ☐ | ☐ | ☐ | |
| 6.4 | Inference API performs input validation and sanitisation | ☐ | ☐ | ☐ | |
| 6.5 | Output confidence is suppressed / perturbed before return | ☐ | ☐ | ☐ | |
| 6.6 | Physical adversarial patch evaluation has been performed | ☐ | ☐ | ☐ | |
| 6.7 | Environmental distortion testing completed (dust, glare, etc.) | ☐ | ☐ | ☐ | |
| 6.8 | Canary audit performed; exposure score < 5 bits | ☐ | ☐ | ☐ | |

---

## Section 7: Network Security

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 7.1 | Device only initiates outbound connections (no open inbound) | ☐ | ☐ | ☐ | |
| 7.2 | All protocols use TLS 1.3; TLS 1.0/1.1 disabled | ☐ | ☐ | ☐ | |
| 7.3 | mTLS enforced between device and backend services | ☐ | ☐ | ☐ | |
| 7.4 | Rate limiting applied to inference / telemetry API | ☐ | ☐ | ☐ | |
| 7.5 | Network firewall rules restrict traffic to known endpoints | ☐ | ☐ | ☐ | |

---

## Section 8: Provisioning & Identity

| # | Check | Pass | Fail | N/A | Evidence / Notes |
|---|-------|------|------|-----|-----------------|
| 8.1 | Each device has a unique, hardware-bound identity | ☐ | ☐ | ☐ | |
| 8.2 | Device identity certificate issued by trusted CA (not self-signed) | ☐ | ☐ | ☐ | |
| 8.3 | Provisioning tokens are single-use and short-lived | ☐ | ☐ | ☐ | |
| 8.4 | Factory provisioning environment is access-controlled | ☐ | ☐ | ☐ | |
| 8.5 | Compromised device can be remotely revoked | ☐ | ☐ | ☐ | |

---

## Checklist Summary

| Section | Total Checks | Pass | Fail | N/A | % Pass |
|---------|-------------|------|------|-----|--------|
| 1. Secure Boot | 7 | | | | |
| 2. Key Management | 8 | | | | |
| 3. TrustZone/TEE | 6 | | | | |
| 4. Debug Hardening | 6 | | | | |
| 5. OTA Security | 6 | | | | |
| 6. ML Model Security | 8 | | | | |
| 7. Network Security | 5 | | | | |
| 8. Provisioning | 5 | | | | |
| **Total** | **51** | | | | |

---

## Deployment Gate

| Gate | Criteria | Result |
|------|----------|--------|
| **Hard gate** | Zero FAIL on Sections 1, 2, 5 | ☐ Pass ☐ Fail |
| **Soft gate** | ≥ 80% Pass across all sections | ☐ Pass ☐ Fail |
| **ML gate** | All Section 6 items Pass or N/A | ☐ Pass ☐ Fail |

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Hardware Security Engineer | | | |
| ML Security Engineer | | | |
| Product Owner | | | |
| CISO / Security Lead | | | |

---

*Template: AI Fortress Chapter 15 · Mohan Krishnamurthy*
