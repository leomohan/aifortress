"""
tests/test_model_encryption_signing.py
AI Fortress · Chapter 6 · Code Sample 6.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import os
import pytest
from pathlib import Path

from model_encryptor import ModelEncryptor
from model_signer import ModelSigner, SignatureManifest
from signature_verifier import SignatureVerifier
from key_rotation import KeyRotationManager
from load_guard import SafeModelLoader, UnsignedModelError, TamperedModelError


def _make_fake_model(path: Path, size_bytes: int = 1024) -> Path:
    """Write a fake model checkpoint file."""
    path.write_bytes(os.urandom(size_bytes))
    return path


class TestModelEncryptor:
    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        kek      = os.urandom(32)
        enc      = ModelEncryptor(backend="local", local_kek=kek, kek_id="test-kek")
        src      = _make_fake_model(tmp_path / "model.pt")
        enc_path = tmp_path / "model.pt.enc"
        dec_path = tmp_path / "model_dec.pt"

        enc.encrypt(src, enc_path)
        enc.decrypt(enc_path, dec_path)

        assert src.read_bytes() == dec_path.read_bytes()

    def test_encrypted_file_differs_from_original(self, tmp_path):
        enc  = ModelEncryptor(backend="local")
        src  = _make_fake_model(tmp_path / "model.pt")
        dst  = tmp_path / "model.enc"
        enc.encrypt(src, dst)
        assert src.read_bytes() != dst.read_bytes()

    def test_manifest_contains_sha256(self, tmp_path):
        enc      = ModelEncryptor(backend="local")
        src      = _make_fake_model(tmp_path / "model.pt", 2048)
        dst      = tmp_path / "model.enc"
        manifest = enc.encrypt(src, dst)
        assert len(manifest.original_sha256) == 64

    def test_wrong_kek_fails_decrypt(self, tmp_path):
        kek1 = os.urandom(32)
        kek2 = os.urandom(32)
        enc1 = ModelEncryptor(backend="local", local_kek=kek1)
        enc2 = ModelEncryptor(backend="local", local_kek=kek2)
        src  = _make_fake_model(tmp_path / "model.pt")
        dst  = tmp_path / "model.enc"
        enc1.encrypt(src, dst)
        with pytest.raises(Exception):
            enc2.decrypt(dst, tmp_path / "out.pt")


class TestModelSigner:
    def test_sign_creates_manifest(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        signer   = ModelSigner.from_new_keypair(signer_id="trainer-1", role="trainer")
        manifest = signer.sign(artefact, model_name="fraud-detector", model_version="1.0")
        manifest_path = artefact.with_suffix(".pt.manifest.json")
        assert manifest_path.exists()
        assert len(manifest.signatures) == 1
        assert manifest.signatures[0].role == "trainer"

    def test_countersign_adds_entry(self, tmp_path):
        artefact  = _make_fake_model(tmp_path / "model.pt")
        signer1   = ModelSigner.from_new_keypair(signer_id="trainer", role="trainer")
        signer2   = ModelSigner.from_new_keypair(signer_id="reviewer", role="reviewer")
        signer1.sign(artefact, model_name="m", model_version="1")
        manifest = signer2.sign(artefact)
        assert len(manifest.signatures) == 2

    def test_tampered_artefact_raises_on_countersign(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        signer1  = ModelSigner.from_new_keypair()
        signer2  = ModelSigner.from_new_keypair()
        signer1.sign(artefact)
        # Tamper
        artefact.write_bytes(os.urandom(1024))
        with pytest.raises(ValueError, match="SHA-256 has changed"):
            signer2.sign(artefact)

    def test_save_and_load_keypair(self, tmp_path):
        signer = ModelSigner.from_new_keypair(signer_id="s1")
        signer.save_keypair(tmp_path / "key.pem", tmp_path / "key.pub")
        loaded = ModelSigner.from_private_key_pem(
            (tmp_path / "key.pem").read_bytes(), signer_id="s1"
        )
        assert loaded.public_key_pem() == signer.public_key_pem()


class TestSignatureVerifier:
    def test_valid_signature_passes(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        signer   = ModelSigner.from_new_keypair(signer_id="s1", role="trainer")
        signer.sign(artefact, model_name="m", model_version="1")
        verifier = SignatureVerifier()
        result   = verifier.verify(artefact)
        assert result.valid
        assert "s1" in result.verified_signers

    def test_missing_manifest_fails(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        verifier = SignatureVerifier()
        result   = verifier.verify(artefact)
        assert not result.valid
        assert any("unsigned" in e.lower() for e in result.errors)

    def test_tampered_artefact_fails(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        signer   = ModelSigner.from_new_keypair()
        signer.sign(artefact)
        artefact.write_bytes(os.urandom(1024))   # tamper
        verifier = SignatureVerifier()
        result   = verifier.verify(artefact)
        assert not result.valid
        assert any("mismatch" in e.lower() for e in result.errors)

    def test_required_role_missing_fails(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        signer   = ModelSigner.from_new_keypair(role="trainer")
        signer.sign(artefact)
        verifier = SignatureVerifier(required_roles=["trainer", "reviewer"])
        result   = verifier.verify(artefact)
        assert not result.valid
        assert any("reviewer" in e for e in result.errors)

    def test_chain_both_roles_passes(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        s1 = ModelSigner.from_new_keypair(signer_id="a", role="trainer")
        s2 = ModelSigner.from_new_keypair(signer_id="b", role="reviewer")
        s1.sign(artefact, model_name="m", model_version="1")
        s2.sign(artefact)
        verifier = SignatureVerifier(required_roles=["trainer", "reviewer"])
        result   = verifier.verify(artefact)
        assert result.valid


class TestKeyRotation:
    def test_rotation_produces_valid_cert(self, tmp_path):
        kek1 = os.urandom(32)
        kek2 = os.urandom(32)
        enc1 = ModelEncryptor(backend="local", local_kek=kek1, kek_id="kek-v1")
        enc2 = ModelEncryptor(backend="local", local_kek=kek2, kek_id="kek-v2")
        src  = _make_fake_model(tmp_path / "model.pt")
        enc_path = tmp_path / "model.enc"
        enc1.encrypt(src, enc_path)

        mgr  = KeyRotationManager(enc1, enc2, operator_id="ops-team")
        cert = mgr.rotate(enc_path, tmp_path / "model.enc.rotated")
        assert cert.old_kek_id == "kek-v1"
        assert cert.new_kek_id == "kek-v2"
        assert len(cert.sha256_proof) == 64

    def test_rotated_file_decryptable_with_new_kek(self, tmp_path):
        kek1 = os.urandom(32)
        kek2 = os.urandom(32)
        enc1 = ModelEncryptor(backend="local", local_kek=kek1, kek_id="kek-v1")
        enc2 = ModelEncryptor(backend="local", local_kek=kek2, kek_id="kek-v2")
        src  = _make_fake_model(tmp_path / "model.pt", 2048)
        enc_path     = tmp_path / "model.enc"
        rotated_path = tmp_path / "model_rotated.enc"
        dec_path     = tmp_path / "model_dec.pt"
        enc1.encrypt(src, enc_path)
        KeyRotationManager(enc1, enc2).rotate(enc_path, rotated_path)
        enc2.decrypt(rotated_path, dec_path)
        assert src.read_bytes() == dec_path.read_bytes()


class TestLoadGuard:
    def test_unsigned_model_raises(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        guard    = SafeModelLoader()
        with pytest.raises(UnsignedModelError):
            guard.verify_only(artefact)

    def test_signed_model_passes(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        signer   = ModelSigner.from_new_keypair(role="trainer")
        signer.sign(artefact, model_name="fraud", model_version="2")
        guard  = SafeModelLoader(expected_name="fraud", expected_version="2")
        result = guard.verify_only(artefact)
        assert result.valid

    def test_wrong_name_raises(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt")
        signer   = ModelSigner.from_new_keypair()
        signer.sign(artefact, model_name="legit-model", model_version="1")
        guard = SafeModelLoader(expected_name="different-model")
        with pytest.raises(TamperedModelError, match="name mismatch"):
            guard.verify_only(artefact)

    def test_load_bytes_returns_content(self, tmp_path):
        artefact = _make_fake_model(tmp_path / "model.pt", 512)
        signer   = ModelSigner.from_new_keypair()
        signer.sign(artefact)
        guard    = SafeModelLoader()
        content  = guard.load_bytes(artefact)
        assert content == artefact.read_bytes()
