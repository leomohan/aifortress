# Ch.15-A — Hardware Root of Trust Integration

**AI Fortress** · Chapter 15: Edge AI & Embedded ML Security

---

## What This Does

Implements TPM 2.0-based hardware attestation and platform integrity
verification for edge AI devices:

- **TPM attestation client** — issues attestation quote requests to a
  TPM 2.0 device; parses the quote structure; verifies the AIK
  (Attestation Identity Key) certificate chain; returns a structured
  `AttestationQuote` with PCR values and nonce binding; simulates the
  full TPM2_Quote flow without requiring physical hardware
- **Secure boot log verifier** — parses TCG Event Log (EFI measured
  boot) entries; replays SHA-256 PCR extension chain; detects log
  tampering via PCR mismatch; flags unexpected boot components
- **Platform integrity checker** — compares current PCR values against
  a known-good baseline (golden measurements); produces a
  `PlatformIntegrityReport` with per-PCR pass/fail status and an
  overall integrity verdict; supports configurable PCR masks

---

## File Structure

```
hrot-integration/
├── README.md
├── requirements.txt
├── tpm_attestation_client.py   # TPM 2.0 quote simulation and verification
├── secure_boot_verifier.py     # TCG event log replay and PCR verification
├── platform_integrity_checker.py # PCR baseline comparison
└── tests/
    └── test_hrot.py
```

> Note: All modules simulate TPM operations using pure Python.
> For production, replace simulation stubs with calls to
> `tpm2-tools`, `python-tpm2`, or the TSS2 Python bindings.
