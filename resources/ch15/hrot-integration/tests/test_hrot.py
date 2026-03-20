"""
tests/test_hrot.py
AI Fortress · Chapter 15 · Code Sample 15.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import hashlib, json, pytest
from pathlib import Path

from tpm_attestation_client import TPMAttestationClient
from secure_boot_verifier import SecureBootVerifier, BootEvent
from platform_integrity_checker import PlatformIntegrityChecker, GoldenBaseline


KEY = b"test-tpm-signing-key-min-32-bytes!!"

# ── TPMAttestationClient ──────────────────────────────────────────────────────

def _pcrs():
    c = TPMAttestationClient(KEY)
    pcr = c.initial_pcr()
    return {
        0: c.extend_pcr(pcr, b"uefi-firmware-v2.1"),
        4: c.extend_pcr(pcr, b"grub-2.06"),
        7: c.extend_pcr(pcr, b"secureboot-enabled"),
    }

class TestTPMAttestationClient:

    def test_quote_produces_record(self):
        c     = TPMAttestationClient(KEY)
        nonce = c.generate_nonce()
        quote = c.quote("dev-001", nonce, _pcrs())
        assert quote.device_id == "dev-001"
        assert quote.nonce == nonce
        assert quote.quote_digest

    def test_verify_valid_quote(self):
        c      = TPMAttestationClient(KEY)
        nonce  = c.generate_nonce()
        quote  = c.quote("dev-001", nonce, _pcrs())
        result = c.verify(quote, nonce)
        assert result.valid
        assert result.nonce_matches
        assert result.signature_ok

    def test_verify_wrong_nonce(self):
        c      = TPMAttestationClient(KEY)
        nonce  = c.generate_nonce()
        quote  = c.quote("dev-001", nonce, _pcrs())
        result = c.verify(quote, "wrong" * 8)
        assert not result.valid
        assert not result.nonce_matches

    def test_verify_tampered_pcr(self):
        c      = TPMAttestationClient(KEY)
        nonce  = c.generate_nonce()
        quote  = c.quote("dev-001", nonce, _pcrs())
        quote.pcr_values[0] = "aa" * 32   # tamper
        result = c.verify(quote, nonce)
        assert not result.valid
        assert not result.signature_ok

    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            TPMAttestationClient(b"short")

    def test_nonce_is_64_hex_chars(self):
        c     = TPMAttestationClient(KEY)
        nonce = c.generate_nonce()
        assert len(nonce) == 64

    def test_extend_pcr_changes_value(self):
        c    = TPMAttestationClient(KEY)
        zero = c.initial_pcr()
        ext  = c.extend_pcr(zero, b"measurement")
        assert ext != zero

    def test_pcr_count_recorded(self):
        c      = TPMAttestationClient(KEY)
        nonce  = c.generate_nonce()
        quote  = c.quote("d", nonce, _pcrs())
        result = c.verify(quote, nonce)
        assert result.pcr_count == 3

    def test_quote_valid_flag_set_after_verify(self):
        c      = TPMAttestationClient(KEY)
        nonce  = c.generate_nonce()
        quote  = c.quote("d", nonce, _pcrs())
        assert not quote.quote_valid
        c.verify(quote, nonce)
        assert quote.quote_valid


# ── SecureBootVerifier ────────────────────────────────────────────────────────

def _events():
    return [
        BootEvent(0, "EV_EFI_VARIABLE_DRIVER_CONFIG", "UEFI-firmware-v2.1", b"uefi-fw"),
        BootEvent(4, "EV_EFI_BOOT_SERVICES_APPLICATION", "grub-2.06", b"grub"),
        BootEvent(7, "EV_EFI_VARIABLE_AUTHORITY", "SecureBoot-db", b"secureboot-db"),
    ]

def _reported_pcrs_from_events(events):
    pcrs = {}
    for ev in events:
        current = pcrs.get(ev.pcr_index, "00" * 32)
        pcrs[ev.pcr_index] = hashlib.sha256(
            bytes.fromhex(current) + ev.measurement
        ).hexdigest()
    return pcrs

class TestSecureBootVerifier:

    def test_valid_log_passes(self):
        events   = _events()
        reported = _reported_pcrs_from_events(events)
        verifier = SecureBootVerifier(
            approved_components={"UEFI-firmware-v2.1", "grub-2.06", "SecureBoot-db"},
            required_events={"UEFI-firmware-v2.1", "SecureBoot-db"},
        )
        result = verifier.verify(events, reported)
        assert result.valid

    def test_pcr_mismatch_detected(self):
        events   = _events()
        reported = _reported_pcrs_from_events(events)
        reported[0] = "bb" * 32   # tamper reported PCR
        verifier = SecureBootVerifier()
        result   = verifier.verify(events, reported)
        assert not result.valid
        assert 0 in result.mismatched_pcrs

    def test_unexpected_component_flagged(self):
        events   = _events() + [BootEvent(4, "EV_UNKNOWN", "malicious-bootkit", b"evil")]
        reported = _reported_pcrs_from_events(events)
        verifier = SecureBootVerifier(
            approved_components={"UEFI-firmware-v2.1", "grub-2.06", "SecureBoot-db"}
        )
        result = verifier.verify(events, reported)
        assert not result.valid
        assert any("malicious" in u for u in result.unexpected_events)

    def test_missing_required_event_flagged(self):
        events   = _events()[:1]   # only firmware event
        reported = _reported_pcrs_from_events(events)
        verifier = SecureBootVerifier(required_events={"SecureBoot-db"})
        result   = verifier.verify(events, reported)
        assert not result.valid
        assert "SecureBoot-db" in result.missing_events

    def test_event_count_recorded(self):
        events   = _events()
        reported = _reported_pcrs_from_events(events)
        verifier = SecureBootVerifier()
        result   = verifier.verify(events, reported)
        assert result.event_count == 3


# ── PlatformIntegrityChecker ──────────────────────────────────────────────────

def _baseline(checker):
    return checker.register_baseline(
        "golden-v1", "edge-cam-x200",
        pcr_values={0: "aa" * 32, 4: "bb" * 32, 7: "cc" * 32, 1: "dd" * 32},
    )

class TestPlatformIntegrityChecker:

    def test_all_pcrs_match(self):
        checker  = PlatformIntegrityChecker(pcr_mask={0, 4, 7})
        baseline = _baseline(checker)
        current  = {0: "aa" * 32, 4: "bb" * 32, 7: "cc" * 32}
        report   = checker.check("dev-001", current, baseline)
        assert report.verdict == "PASS"
        assert len(report.failed_pcrs) == 0

    def test_pcr_mismatch_fails(self):
        checker  = PlatformIntegrityChecker(pcr_mask={0, 4, 7})
        baseline = _baseline(checker)
        current  = {0: "ff" * 32, 4: "bb" * 32, 7: "cc" * 32}   # PCR0 tampered
        report   = checker.check("dev-001", current, baseline)
        assert report.verdict == "FAIL"
        assert 0 in report.failed_pcrs

    def test_masked_pcr_not_evaluated(self):
        checker  = PlatformIntegrityChecker(pcr_mask={0, 7})   # PCR4 masked
        baseline = _baseline(checker)
        current  = {0: "aa" * 32, 4: "99" * 32, 7: "cc" * 32}   # PCR4 wrong but masked
        report   = checker.check("dev-001", current, baseline)
        assert report.verdict == "PASS"
        assert 4 in report.masked_pcrs

    def test_missing_pcr_fails(self):
        checker  = PlatformIntegrityChecker(pcr_mask={0, 4, 7})
        baseline = _baseline(checker)
        report   = checker.check("dev-001", {}, baseline)   # no PCR values
        assert report.verdict == "FAIL"

    def test_save_json(self, tmp_path):
        checker  = PlatformIntegrityChecker(pcr_mask={0})
        baseline = checker.register_baseline("b", "cls", {0: "aa" * 32})
        report   = checker.check("d", {0: "aa" * 32}, baseline)
        p        = tmp_path / "report.json"
        report.save_json(p)
        data     = json.loads(p.read_text())
        assert data["verdict"] == "PASS"

    def test_baseline_id_recorded(self):
        checker  = PlatformIntegrityChecker(pcr_mask={0})
        baseline = checker.register_baseline("golden-v2", "cls", {0: "aa" * 32})
        report   = checker.check("d", {0: "aa" * 32}, baseline)
        assert report.baseline_id == "golden-v2"
