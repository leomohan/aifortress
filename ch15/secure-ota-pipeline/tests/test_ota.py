"""
tests/test_ota.py
AI Fortress · Chapter 15 · Code Sample 15.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import pytest
from ota_package_builder import OTAPackageBuilder
from ota_verifier import OTAVerifier
from rollback_guard import RollbackGuard

KEY = b"ota-signing-key-minimum-32-bytes!!"


# ── OTAPackageBuilder ─────────────────────────────────────────────────────────

class TestOTAPackageBuilder:

    def test_build_package(self):
        builder = OTAPackageBuilder(KEY)
        pkg     = builder.build(b"model weights v2", "2.0.0", "edge-cam")
        assert pkg.metadata.target_version == "2.0.0"
        assert len(pkg.signature) == 32

    def test_signature_tied_to_payload(self):
        builder = OTAPackageBuilder(KEY)
        pkg1    = builder.build(b"payload-a", "1.0.0", "cam")
        pkg2    = builder.build(b"payload-b", "1.0.0", "cam")
        assert pkg1.signature != pkg2.signature

    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            OTAPackageBuilder(b"short")

    def test_save_and_load(self, tmp_path):
        builder = OTAPackageBuilder(KEY)
        pkg     = builder.build(b"firmware data", "3.0.0", "cam", "firmware")
        p       = tmp_path / "update.ota"
        pkg.save(p)
        meta, payload, sig = OTAPackageBuilder.load(p)
        assert meta["target_version"] == "3.0.0"
        assert payload == b"firmware data"

    def test_payload_hash_in_metadata(self):
        import hashlib
        builder = OTAPackageBuilder(KEY)
        pt      = b"model weights"
        pkg     = builder.build(pt, "1.0.0", "cam")
        assert pkg.metadata.payload_sha256 == hashlib.sha256(pt).hexdigest()


# ── OTAVerifier ───────────────────────────────────────────────────────────────

class TestOTAVerifier:

    def _pkg(self, version="2.0.0", device_class="edge-cam"):
        return OTAPackageBuilder(KEY).build(b"model data", version, device_class)

    def test_valid_package_passes(self):
        verifier = OTAVerifier(KEY, current_version="1.0.0", device_class="edge-cam")
        result   = verifier.verify(self._pkg())
        assert result.valid

    def test_tampered_payload_fails(self):
        verifier = OTAVerifier(KEY, "1.0.0", "edge-cam")
        pkg      = self._pkg()
        pkg.payload = b"tampered payload"
        result   = verifier.verify(pkg)
        assert not result.valid
        assert not result.payload_hash_ok

    def test_tampered_signature_fails(self):
        verifier = OTAVerifier(KEY, "1.0.0", "edge-cam")
        pkg      = self._pkg()
        pkg.signature = b"\xff" * 32
        result   = verifier.verify(pkg)
        assert not result.valid
        assert not result.signature_ok

    def test_wrong_device_class_fails(self):
        verifier = OTAVerifier(KEY, "1.0.0", "other-device")
        result   = verifier.verify(self._pkg())
        assert not result.valid
        assert not result.device_class_ok

    def test_version_downgrade_blocked(self):
        verifier = OTAVerifier(KEY, current_version="3.0.0", device_class="edge-cam")
        result   = verifier.verify(self._pkg(version="2.0.0"))
        assert not result.valid
        assert not result.version_ok

    def test_package_id_recorded(self):
        verifier = OTAVerifier(KEY, "1.0.0", "edge-cam")
        pkg      = self._pkg()
        result   = verifier.verify(pkg)
        assert result.package_id == pkg.metadata.package_id


# ── RollbackGuard ─────────────────────────────────────────────────────────────

class TestRollbackGuard:

    def test_newer_version_allowed(self, tmp_path):
        guard  = RollbackGuard(tmp_path / "arc.json", "1.0.0")
        result = guard.check("2.0.0")
        assert result.allowed

    def test_same_version_blocked(self, tmp_path):
        guard  = RollbackGuard(tmp_path / "arc.json", "1.0.0")
        result = guard.check("1.0.0")
        assert not result.allowed

    def test_older_version_blocked(self, tmp_path):
        guard  = RollbackGuard(tmp_path / "arc.json", "2.0.0")
        result = guard.check("1.9.9")
        assert not result.allowed

    def test_advance_updates_minimum(self, tmp_path):
        guard = RollbackGuard(tmp_path / "arc.json", "1.0.0")
        guard.advance("2.0.0")
        assert guard.minimum_version == "2.0.0"
        assert not guard.check("1.9.9").allowed

    def test_advance_requires_greater(self, tmp_path):
        guard = RollbackGuard(tmp_path / "arc.json", "2.0.0")
        with pytest.raises(ValueError):
            guard.advance("1.0.0")

    def test_persists_across_instances(self, tmp_path):
        p = tmp_path / "arc.json"
        g1 = RollbackGuard(p, "1.0.0")
        g1.advance("3.0.0")
        g2 = RollbackGuard(p)
        assert g2.minimum_version == "3.0.0"

    def test_emergency_override_recorded(self, tmp_path):
        guard    = RollbackGuard(tmp_path / "arc.json", "3.0.0")
        override = guard.emergency_override("2.0.0", "security-team", "critical patch")
        assert override.override
        assert "OVERRIDE" in override.updated_by
        # Minimum NOT lowered
        assert guard.minimum_version == "3.0.0"

    def test_history_tracked(self, tmp_path):
        guard = RollbackGuard(tmp_path / "arc.json", "1.0.0")
        guard.advance("2.0.0")
        guard.advance("3.0.0")
        assert len(guard.history()) == 2
