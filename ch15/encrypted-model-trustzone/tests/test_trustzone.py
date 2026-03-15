"""
tests/test_trustzone.py
AI Fortress · Chapter 15 · Code Sample 15.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import pytest
from model_encryption import ModelEncryptor
from secure_enclave_loader import SecureEnclaveLoader
from memory_isolation_verifier import MemoryIsolationVerifier, MemoryRegion

KEY_32 = b"test-aes-256-key-exactly-32bytes"
KEY_VER = b"verify-key-32-bytes-exactly-here!"

# ── ModelEncryptor ────────────────────────────────────────────────────────────

class TestModelEncryptor:

    def test_encrypt_decrypt_roundtrip(self):
        enc    = ModelEncryptor(KEY_32)
        pt     = b"fake model weights 0123456789"
        pkg    = enc.encrypt(pt, "fraud-v2")
        result = enc.decrypt(pkg)
        assert result.success
        assert result.plaintext == pt

    def test_encrypt_changes_bytes(self):
        enc = ModelEncryptor(KEY_32)
        pt  = b"model weights"
        pkg = enc.encrypt(pt, "m")
        assert pkg.ciphertext != pt

    def test_tampered_ciphertext_fails(self):
        enc   = ModelEncryptor(KEY_32)
        pkg   = enc.encrypt(b"weights", "m")
        tampered = bytearray(pkg.ciphertext)
        tampered[0] ^= 0xFF
        pkg.ciphertext = bytes(tampered)
        result = enc.decrypt(pkg)
        assert not result.success

    def test_wrong_key_fails(self):
        enc1  = ModelEncryptor(KEY_32)
        enc2  = ModelEncryptor(b"different-key-also-32-bytes-here")
        pkg   = enc1.encrypt(b"weights", "m")
        result = enc2.decrypt(pkg)
        assert not result.success

    def test_wrong_key_size_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ModelEncryptor(b"tooshort")

    def test_nonce_unique_per_call(self):
        enc  = ModelEncryptor(KEY_32)
        pkg1 = enc.encrypt(b"weights", "m")
        pkg2 = enc.encrypt(b"weights", "m")
        assert pkg1.nonce != pkg2.nonce

    def test_plaintext_hash_stored(self):
        import hashlib
        enc = ModelEncryptor(KEY_32)
        pt  = b"model data here"
        pkg = enc.encrypt(pt, "m")
        assert pkg.plaintext_sha256 == hashlib.sha256(pt).hexdigest()

    def test_integrity_ok_flag(self):
        enc    = ModelEncryptor(KEY_32)
        pkg    = enc.encrypt(b"weights", "m")
        result = enc.decrypt(pkg)
        assert result.integrity_ok

    def test_save_creates_files(self, tmp_path):
        enc = ModelEncryptor(KEY_32)
        pkg = enc.encrypt(b"weights", "m")
        pkg.save(tmp_path / "model.enc")
        assert (tmp_path / "model.enc").exists()
        assert (tmp_path / "model.meta.json").exists()


# ── SecureEnclaveLoader ───────────────────────────────────────────────────────

def _infer_fn(weights, inputs):
    return f"result:{len(weights)}:{inputs}"

class TestSecureEnclaveLoader:

    def _loader(self):
        return SecureEnclaveLoader("ta-fraud-v1", KEY_VER, _infer_fn)

    def test_open_session_returns_session(self):
        loader  = self._loader()
        session = loader.open_session("fraud-v2", b"weights")
        assert session.active
        assert session.model_id == "fraud-v2"

    def test_invoke_returns_result(self):
        loader  = self._loader()
        session = loader.open_session("fraud-v2", b"weights-data")
        result  = loader.invoke(session.session_id, "test-input")
        assert result.output
        assert not result.weights_leaked

    def test_weights_not_in_result(self):
        loader  = self._loader()
        session = loader.open_session("m", b"secret-weights")
        result  = loader.invoke(session.session_id, "x")
        assert b"secret-weights" not in str(result.output).encode()

    def test_close_session_deactivates(self):
        loader  = self._loader()
        session = loader.open_session("m", b"w")
        loader.close_session(session.session_id)
        assert not session.active

    def test_invoke_closed_session_raises(self):
        loader  = self._loader()
        session = loader.open_session("m", b"w")
        loader.close_session(session.session_id)
        with pytest.raises(ValueError):
            loader.invoke(session.session_id, "x")

    def test_inference_count_increments(self):
        loader  = self._loader()
        session = loader.open_session("m", b"w")
        loader.invoke(session.session_id, "a")
        loader.invoke(session.session_id, "b")
        assert session.inference_count == 2

    def test_active_sessions_list(self):
        loader = self._loader()
        s1     = loader.open_session("m1", b"w1")
        s2     = loader.open_session("m2", b"w2")
        loader.close_session(s1.session_id)
        active = loader.active_sessions()
        assert len(active) == 1
        assert active[0].session_id == s2.session_id


# ── MemoryIsolationVerifier ───────────────────────────────────────────────────

def _regions():
    return [
        MemoryRegion("tee-os",      0x0E000000, 0x01000000, "secure", "RWX"),
        MemoryRegion("model-weights", 0x0D000000, 0x01000000, "secure", "RW"),
        MemoryRegion("normal-app",  0x40000000, 0x10000000, "normal", "RWX"),
        MemoryRegion("shared-buf",  0x0F000000, 0x00100000, "shared", "RW"),
    ]

class TestMemoryIsolationVerifier:

    def test_valid_layout_passes(self):
        v      = MemoryIsolationVerifier()
        report = v.verify(_regions(), model_region_names=["model-weights"])
        assert report.valid
        assert len(report.violations) == 0

    def test_overlap_detected(self):
        regions = _regions() + [
            MemoryRegion("rogue-normal", 0x0D500000, 0x00100000, "normal", "RW")
        ]
        v      = MemoryIsolationVerifier()
        report = v.verify(regions, model_region_names=["model-weights"])
        assert not report.valid
        assert any(viol.kind == "overlap" for viol in report.violations)

    def test_model_in_normal_world_flagged(self):
        regions = _regions().copy()
        # Replace secure model region with normal world one
        regions[1] = MemoryRegion("model-weights", 0x0D000000, 0x01000000, "normal", "RW")
        v      = MemoryIsolationVerifier()
        report = v.verify(regions, model_region_names=["model-weights"])
        assert not report.valid
        assert any(viol.kind == "wrong_world" for viol in report.violations)

    def test_exec_on_shared_flagged(self):
        regions = _regions().copy()
        regions[-1] = MemoryRegion("shared-buf", 0x0F000000, 0x00100000, "shared", "RWX")
        v      = MemoryIsolationVerifier()
        report = v.verify(regions)
        assert not report.valid
        assert any(viol.kind == "exec_in_normal" for viol in report.violations)

    def test_checked_regions_count(self):
        v      = MemoryIsolationVerifier()
        report = v.verify(_regions())
        assert report.checked_regions == len(_regions())

    def test_empty_regions(self):
        v      = MemoryIsolationVerifier()
        report = v.verify([])
        assert report.valid
