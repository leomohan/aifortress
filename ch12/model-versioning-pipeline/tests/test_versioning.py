"""
tests/test_versioning.py
AI Fortress · Chapter 12 · Code Sample 12.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import hashlib, json, pytest
from pathlib import Path

from version_registry import VersionRegistry, parse_semver, compare_semver
from artefact_signer import ArtefactSigner
from content_addressable_store import ContentAddressableStore
from promotion_gate import PromotionGate
from version_lineage import VersionLineageGraph


KEY = b"test-signing-key-minimum-32-bytes!!"


# ── VersionRegistry ───────────────────────────────────────────────────────────

class TestVersionRegistry:

    def test_register_valid_version(self):
        reg = VersionRegistry()
        mv  = reg.register("fraud-model", "1.0.0", "ci-pipeline")
        assert mv.version == "1.0.0"

    def test_duplicate_version_raises(self):
        reg = VersionRegistry()
        reg.register("m", "1.0.0", "ci")
        with pytest.raises(ValueError, match="already registered"):
            reg.register("m", "1.0.0", "ci")

    def test_downgrade_raises(self):
        reg = VersionRegistry()
        reg.register("m", "2.0.0", "ci")
        with pytest.raises(ValueError, match="not greater than"):
            reg.register("m", "1.9.9", "ci")

    def test_invalid_semver_raises(self):
        reg = VersionRegistry()
        with pytest.raises(ValueError, match="Invalid SemVer"):
            reg.register("m", "v1.0", "ci")

    def test_get_latest(self):
        reg = VersionRegistry()
        reg.register("m", "1.0.0", "ci")
        reg.register("m", "1.1.0", "ci")
        assert reg.get_latest("m").version == "1.1.0"

    def test_get_history_ordered(self):
        reg = VersionRegistry()
        for v in ("1.0.0", "1.1.0", "2.0.0"):
            reg.register("m", v, "ci")
        hist = reg.get_history("m")
        assert [mv.version for mv in hist.versions] == ["1.0.0", "1.1.0", "2.0.0"]

    def test_pre_release_less_than_release(self):
        assert compare_semver("2.0.0-rc.1", "2.0.0") == -1

    def test_pre_release_registration_then_release(self):
        reg = VersionRegistry()
        reg.register("m", "2.0.0-rc.1", "ci")
        reg.register("m", "2.0.0", "ci")
        assert reg.get_latest("m").version == "2.0.0"

    def test_get_version_by_name(self):
        reg = VersionRegistry()
        reg.register("m", "1.0.0", "ci", description="initial")
        mv  = reg.get_version("m", "1.0.0")
        assert mv.description == "initial"

    def test_list_models(self):
        reg = VersionRegistry()
        reg.register("model-a", "1.0.0", "ci")
        reg.register("model-b", "1.0.0", "ci")
        assert reg.list_models() == ["model-a", "model-b"]

    def test_artefact_hash_stored(self):
        reg = VersionRegistry()
        mv  = reg.register("m", "1.0.0", "ci", artefact_hash="abc123")
        assert mv.artefact_hash == "abc123"

    def test_audit_log_written(self, tmp_path):
        log = tmp_path / "reg.jsonl"
        reg = VersionRegistry(audit_path=log)
        reg.register("m", "1.0.0", "ci")
        data = json.loads(log.read_text().splitlines()[0])
        assert data["event"] == "version_registered"


# ── ArtefactSigner ────────────────────────────────────────────────────────────

class TestArtefactSigner:

    def test_sign_produces_record(self):
        signer  = ArtefactSigner(KEY, signer="test-pipeline")
        payload = b"fake model weights 123"
        record  = signer.sign(payload, "fraud-model", "1.0.0")
        assert record.sha256
        assert record.signature
        assert record.algorithm == "hmac-sha256"
        assert record.model_name == "fraud-model"

    def test_verify_valid(self):
        signer  = ArtefactSigner(KEY)
        payload = b"model bytes here"
        record  = signer.sign(payload, "nlp-model", "2.0.0")
        result  = signer.verify(payload, record)
        assert result.valid
        assert result.digest_ok
        assert result.signature_ok

    def test_verify_tampered_bytes(self):
        signer  = ArtefactSigner(KEY)
        payload = b"original model bytes"
        record  = signer.sign(payload, "m", "1.0.0")
        result  = signer.verify(b"tampered model bytes", record)
        assert not result.valid
        assert not result.digest_ok

    def test_verify_wrong_key(self):
        signer1 = ArtefactSigner(b"key-one-minimum-thirty-two-bytes!!")
        signer2 = ArtefactSigner(b"key-two-minimum-thirty-two-bytes!!")
        payload = b"model bytes"
        record  = signer1.sign(payload, "m", "1.0.0")
        result  = signer2.verify(payload, record)
        assert not result.valid
        assert not result.signature_ok

    def test_short_key_raises(self):
        with pytest.raises(ValueError, match="32 bytes"):
            ArtefactSigner(b"tooshort")

    def test_verify_from_digest(self):
        signer  = ArtefactSigner(KEY)
        payload = b"model weights"
        record  = signer.sign(payload, "m", "1.0.0")
        result  = signer.verify_from_digest(record.sha256, record)
        assert result.valid

    def test_save_json(self, tmp_path):
        signer = ArtefactSigner(KEY)
        record = signer.sign(b"weights", "m", "1.0.0")
        p      = tmp_path / "sig.json"
        record.save_json(p)
        data = json.loads(p.read_text())
        assert "sha256" in data and "signature" in data


# ── ContentAddressableStore ───────────────────────────────────────────────────

class TestContentAddressableStore:

    def _hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def test_put_and_get_by_hash(self):
        store = ContentAddressableStore()
        h     = self._hash(b"weights")
        store.put(h, "m", "1.0.0", size_bytes=7)
        result = store.get_by_hash(h)
        assert result.found
        assert result.entry.model_name == "m"

    def test_get_by_version(self):
        store = ContentAddressableStore()
        h     = self._hash(b"weights")
        store.put(h, "fraud", "1.0.0", size_bytes=7)
        result = store.get_by_version("fraud", "1.0.0")
        assert result.found
        assert result.entry.sha256 == h

    def test_hash_mismatch_tamper_detected(self):
        store = ContentAddressableStore()
        h     = self._hash(b"weights")
        store.put(h, "m", "1.0.0", size_bytes=7)
        bad_h = self._hash(b"different weights")
        result = store.get_by_version("m", "1.0.0", verify_hash=bad_h)
        assert result.tampered

    def test_substitution_attempt_raises(self):
        store = ContentAddressableStore()
        h1    = self._hash(b"weights-v1")
        h2    = self._hash(b"weights-v2-tampered")
        store.put(h1, "m", "1.0.0", size_bytes=10)
        with pytest.raises(ValueError, match="substitution"):
            store.put(h2, "m", "1.0.0", size_bytes=10)

    def test_idempotent_same_hash(self):
        store = ContentAddressableStore()
        h     = self._hash(b"weights")
        store.put(h, "m", "1.0.0", size_bytes=7)
        store.put(h, "m", "1.0.0", size_bytes=7)   # same hash, no error
        assert store.total_entries() == 1

    def test_list_versions(self):
        store = ContentAddressableStore()
        for v in ("1.0.0", "1.1.0", "2.0.0"):
            store.put(self._hash(v.encode()), "m", v, size_bytes=5)
        assert store.list_versions("m") == ["1.0.0", "1.1.0", "2.0.0"]

    def test_persist_and_reload(self, tmp_path):
        p     = tmp_path / "store.json"
        store = ContentAddressableStore(store_path=p)
        h     = self._hash(b"weights")
        store.put(h, "m", "1.0.0", size_bytes=7)
        store2 = ContentAddressableStore(store_path=p)
        result = store2.get_by_version("m", "1.0.0")
        assert result.found

    def test_not_found_returns_false(self):
        store  = ContentAddressableStore()
        result = store.get_by_hash("nonexistent")
        assert not result.found


# ── PromotionGate ─────────────────────────────────────────────────────────────

class TestPromotionGate:

    def test_register_starts_at_dev(self):
        gate   = PromotionGate()
        status = gate.register_version("m", "1.0.0")
        assert status.stage == "dev"

    def test_promote_dev_to_staging(self):
        gate = PromotionGate()
        gate.register_version("m", "1.0.0")
        rec  = gate.promote("m", "1.0.0", approver="ml-lead")
        assert rec.decision  == "approved"
        assert rec.to_stage  == "staging"
        assert gate.get_status("m", "1.0.0").stage == "staging"

    def test_promote_staging_to_production(self):
        gate = PromotionGate()
        gate.register_version("m", "1.0.0")
        gate.promote("m", "1.0.0", approver="ml-lead")
        gate.promote("m", "1.0.0", approver="release-manager")
        assert gate.get_status("m", "1.0.0").stage == "production"
        assert gate.get_status("m", "1.0.0").is_production

    def test_promote_at_production_raises(self):
        gate = PromotionGate()
        gate.register_version("m", "1.0.0")
        gate.promote("m", "1.0.0", "approver")
        gate.promote("m", "1.0.0", "approver")
        with pytest.raises(ValueError, match="already at"):
            gate.promote("m", "1.0.0", "approver")

    def test_auto_approve_blocks(self):
        gate = PromotionGate(auto_approve_fn=lambda m, v, s: False)
        gate.register_version("m", "1.0.0")
        rec  = gate.promote("m", "1.0.0", "approver")
        assert rec.decision == "blocked"
        assert gate.get_status("m", "1.0.0").stage == "dev"

    def test_explicit_block(self):
        gate = PromotionGate()
        gate.register_version("m", "1.0.0")
        rec  = gate.block("m", "1.0.0", "security-team", "Drift detected in evaluation")
        assert rec.decision == "blocked"

    def test_versions_at_stage(self):
        gate = PromotionGate()
        gate.register_version("a", "1.0.0")
        gate.register_version("b", "1.0.0")
        gate.promote("a", "1.0.0", "approver")
        at_staging = gate.versions_at_stage("staging")
        assert ("a", "1.0.0") in at_staging
        assert ("b", "1.0.0") not in at_staging

    def test_unregistered_version_raises(self):
        gate = PromotionGate()
        with pytest.raises(KeyError):
            gate.promote("ghost", "9.9.9", "approver")

    def test_audit_log(self, tmp_path):
        log  = tmp_path / "gate.jsonl"
        gate = PromotionGate(audit_path=log)
        gate.register_version("m", "1.0.0")
        gate.promote("m", "1.0.0", "approver")
        events = {json.loads(l)["event"] for l in log.read_text().splitlines() if l}
        assert "promotion_approved" in events


# ── VersionLineageGraph ───────────────────────────────────────────────────────

class TestVersionLineageGraph:

    def _chain(self):
        g = VersionLineageGraph()
        g.add_relationship("base", "1.0.0", "fine-tune-a", "1.0.0", "fine_tune")
        g.add_relationship("fine-tune-a", "1.0.0", "distilled", "1.0.0", "distillation")
        return g

    def test_add_relationship(self):
        g = self._chain()
        assert "base@1.0.0" in g._nodes

    def test_ancestors(self):
        g       = self._chain()
        result  = g.ancestors("distilled", "1.0.0")
        assert "fine-tune-a@1.0.0" in result.ancestors
        assert "base@1.0.0"        in result.ancestors

    def test_descendants(self):
        g    = self._chain()
        desc = g.descendants("base", "1.0.0")
        assert "fine-tune-a@1.0.0" in desc
        assert "distilled@1.0.0"   in desc

    def test_roots(self):
        g     = self._chain()
        roots = g.roots()
        assert "base@1.0.0" in roots
        assert "fine-tune-a@1.0.0" not in roots

    def test_leaves(self):
        g      = self._chain()
        leaves = g.leaves()
        assert "distilled@1.0.0"   in leaves
        assert "fine-tune-a@1.0.0" not in leaves

    def test_no_cycle(self):
        g      = self._chain()
        report = g.detect_cycles()
        assert not report.has_cycle

    def test_cycle_detected(self):
        g = VersionLineageGraph()
        g.add_relationship("a", "1.0.0", "b", "1.0.0")
        g.add_relationship("b", "1.0.0", "a", "1.0.0")   # cycle
        report = g.detect_cycles()
        assert report.has_cycle

    def test_depth(self):
        g      = self._chain()
        result = g.ancestors("distilled", "1.0.0")
        assert result.depth >= 2

    def test_edges_for(self):
        g     = self._chain()
        edges = g.edges_for("fine-tune-a", "1.0.0")
        rels  = {e.rel for e in edges}
        assert "fine_tune"    in rels
        assert "distillation" in rels

    def test_to_adjacency(self):
        g   = self._chain()
        adj = g.to_adjacency()
        assert "fine-tune-a@1.0.0" in adj["base@1.0.0"]

    def test_isolated_version(self):
        g = VersionLineageGraph()
        g.add_version("solo", "1.0.0")
        assert "solo@1.0.0" in g.roots()
        assert "solo@1.0.0" in g.leaves()
