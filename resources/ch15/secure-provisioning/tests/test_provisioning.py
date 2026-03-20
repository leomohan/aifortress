"""
tests/test_provisioning.py
AI Fortress · Chapter 15 · Code Sample 15.D
Run: pytest tests/ -v
"""
from __future__ import annotations
import pytest
from device_identity_issuer import DeviceIdentityIssuer
from cert_chain_verifier import CertChainVerifier
from attestation_token_validator import AttestationTokenValidator

CA_KEY = b"ca-signing-key-minimum-32-bytes!!"
TOKEN_KEY = b"token-signing-key-minimum-32-bytes!"


# ── DeviceIdentityIssuer ──────────────────────────────────────────────────────

class TestDeviceIdentityIssuer:

    def test_issue_cert(self):
        issuer = DeviceIdentityIssuer(CA_KEY)
        cert   = issuer.issue("SN-001", "edge-cam", b"pubkey-bytes")
        assert cert.device_id
        assert cert.serial_number == "SN-001"
        assert cert.signature

    def test_verify_cert_valid(self):
        issuer = DeviceIdentityIssuer(CA_KEY)
        cert   = issuer.issue("SN-002", "edge-cam", b"pk")
        assert issuer.verify_cert(cert)

    def test_verify_tampered_cert_fails(self):
        issuer        = DeviceIdentityIssuer(CA_KEY)
        cert          = issuer.issue("SN-003", "edge-cam", b"pk")
        cert.device_class = "tampered-class"
        assert not issuer.verify_cert(cert)

    def test_wrong_ca_key_fails(self):
        issuer1 = DeviceIdentityIssuer(CA_KEY)
        issuer2 = DeviceIdentityIssuer(b"different-ca-key-32-bytes-exactly")
        cert    = issuer1.issue("SN-004", "cam", b"pk")
        assert not issuer2.verify_cert(cert)

    def test_short_ca_key_raises(self):
        with pytest.raises(ValueError):
            DeviceIdentityIssuer(b"short")

    def test_issue_provisioning_token(self):
        issuer = DeviceIdentityIssuer(CA_KEY)
        cert   = issuer.issue("SN-005", "cam", b"pk")
        token  = issuer.issue_provisioning_token(cert.device_id)
        assert token.device_id == cert.device_id
        assert len(token.token) == 64

    def test_issued_count(self):
        issuer = DeviceIdentityIssuer(CA_KEY)
        issuer.issue("SN-A", "cam", b"pk")
        issuer.issue("SN-B", "cam", b"pk")
        assert issuer.issued_count() == 2

    def test_public_key_hash_stored(self):
        import hashlib
        issuer = DeviceIdentityIssuer(CA_KEY)
        pk     = b"device-public-key-bytes"
        cert   = issuer.issue("SN-006", "cam", pk)
        assert cert.public_key_hash == hashlib.sha256(pk).hexdigest()


# ── CertChainVerifier ─────────────────────────────────────────────────────────

class TestCertChainVerifier:

    def test_single_cert_valid(self):
        issuer   = DeviceIdentityIssuer(CA_KEY, issuer="root-ca")
        cert     = issuer.issue("SN-C", "cam", b"pk")
        verifier = CertChainVerifier({"root-ca": CA_KEY})
        result   = verifier.verify_chain([cert])
        assert result.valid

    def test_tampered_cert_fails(self):
        issuer   = DeviceIdentityIssuer(CA_KEY, issuer="root-ca")
        cert     = issuer.issue("SN-D", "cam", b"pk")
        cert.serial_number = "TAMPERED"
        verifier = CertChainVerifier({"root-ca": CA_KEY})
        result   = verifier.verify_chain([cert])
        assert not result.valid

    def test_unknown_issuer_fails(self):
        issuer   = DeviceIdentityIssuer(CA_KEY, issuer="unknown-ca")
        cert     = issuer.issue("SN-E", "cam", b"pk")
        verifier = CertChainVerifier({"root-ca": CA_KEY})
        result   = verifier.verify_chain([cert])
        assert not result.valid
        assert any("Unknown issuer" in f for f in result.failures)

    def test_empty_chain_fails(self):
        verifier = CertChainVerifier({"root-ca": CA_KEY})
        result   = verifier.verify_chain([])
        assert not result.valid

    def test_chain_length_recorded(self):
        issuer   = DeviceIdentityIssuer(CA_KEY, issuer="root-ca")
        c1       = issuer.issue("SN-F", "cam", b"pk1")
        c2       = issuer.issue("SN-G", "cam", b"pk2")
        verifier = CertChainVerifier({"root-ca": CA_KEY})
        result   = verifier.verify_chain([c1, c2])
        assert result.chain_length == 2


# ── AttestationTokenValidator ─────────────────────────────────────────────────

class TestAttestationTokenValidator:

    def test_valid_token(self):
        v      = AttestationTokenValidator(TOKEN_KEY)
        token  = v.issue("device-abc")
        result = v.validate(token)
        assert result.valid
        assert result.device_id == "device-abc"

    def test_replay_blocked(self):
        v      = AttestationTokenValidator(TOKEN_KEY)
        token  = v.issue("device-abc")
        v.validate(token)
        result = v.validate(token)   # second use
        assert not result.valid
        assert "already used" in result.reason

    def test_tampered_token_fails(self):
        v         = AttestationTokenValidator(TOKEN_KEY)
        token     = v.issue("device-xyz")
        token.device_id = "hacked-device"
        result    = v.validate(token)
        assert not result.valid

    def test_wrong_key_fails(self):
        issuer    = AttestationTokenValidator(TOKEN_KEY)
        validator = AttestationTokenValidator(b"different-key-also-32-bytes-long!")
        token     = issuer.issue("dev")
        result    = validator.validate(token)
        assert not result.valid

    def test_short_key_raises(self):
        with pytest.raises(ValueError):
            AttestationTokenValidator(b"short")

    def test_token_id_unique(self):
        v  = AttestationTokenValidator(TOKEN_KEY)
        t1 = v.issue("d")
        t2 = v.issue("d")
        assert t1.token_id != t2.token_id
