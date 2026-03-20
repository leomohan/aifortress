"""
tests/test_cicd_hardening.py
AI Fortress · Chapter 8 · Code Sample 8.D
Run: pytest tests/ -v
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import pytest

from provenance_generator import ProvenanceGenerator, BuildSubject
from pinned_action_verifier import PinnedActionVerifier
from build_attestation import BuildAttestationCapture
from artefact_signer import ArtefactSigner


# ── ProvenanceGenerator ───────────────────────────────────────────────────────

class TestProvenanceGenerator:
    SHA = "a" * 40

    def test_generates_slsa_statement(self):
        gen  = ProvenanceGenerator("https://github.com/actions/runner")
        subj = BuildSubject(name="model.pt", sha256="b" * 64)
        prov = gen.generate([subj], "https://github.com/org/repo", "main", self.SHA)
        d    = prov.to_dict()
        assert d["predicateType"]  == "https://slsa.dev/provenance/v0.2"
        assert d["_type"]          == "https://in-toto.io/Statement/v0.1"
        assert len(d["subject"]) == 1
        assert d["subject"][0]["name"] == "model.pt"

    def test_source_sha_in_materials(self):
        gen  = ProvenanceGenerator()
        subj = BuildSubject(name="m.pt", sha256="c" * 64)
        prov = gen.generate([subj], "https://github.com/org/r", "main", self.SHA)
        d    = prov.to_dict()
        materials = d["predicate"]["materials"]
        assert any(self.SHA in str(m) for m in materials)

    def test_build_params_recorded(self):
        gen    = ProvenanceGenerator()
        subj   = BuildSubject(name="m.pt", sha256="d" * 64)
        params = {"lr": 0.001, "epochs": 10}
        prov   = gen.generate([subj], "repo", "main", self.SHA, build_params=params)
        d      = prov.to_dict()
        assert d["predicate"]["invocation"]["parameters"] == params

    def test_save_and_reload(self, tmp_path):
        gen  = ProvenanceGenerator()
        subj = BuildSubject(name="m.pt", sha256="e" * 64)
        prov = gen.generate([subj], "repo", "main", self.SHA)
        path = tmp_path / "provenance.json"
        prov.save(path)
        loaded = json.loads(path.read_text())
        assert loaded["predicateType"] == "https://slsa.dev/provenance/v0.2"

    def test_subject_from_file(self, tmp_path):
        f   = tmp_path / "model.pt"
        f.write_bytes(os.urandom(1024))
        subj = ProvenanceGenerator.subject_from_file(f)
        expected = hashlib.sha256(f.read_bytes()).hexdigest()
        assert subj.sha256 == expected
        assert subj.name   == "model.pt"


# ── PinnedActionVerifier ──────────────────────────────────────────────────────

class TestPinnedActionVerifier:
    PINNED_SHA = "a" * 40
    PINNED_WF  = f"""
name: Train
on: push
jobs:
  train:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PINNED_SHA}
      - uses: actions/setup-python@{PINNED_SHA}
"""
    UNPINNED_WF = """
name: Train
on: push
jobs:
  train:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@main
      - uses: docker://ghcr.io/org/image:latest
"""

    def test_pinned_workflow_passes(self):
        v      = PinnedActionVerifier()
        report = v._verify_text(self.PINNED_WF, "workflow.yml")
        assert report.overall_pass
        assert report.pinned == 2
        assert report.unpinned == 0

    def test_unpinned_tags_detected(self):
        v      = PinnedActionVerifier()
        report = v._verify_text(self.UNPINNED_WF, "workflow.yml")
        assert not report.overall_pass
        assert report.unpinned >= 2

    def test_docker_refs_skipped(self):
        v   = PinnedActionVerifier()
        wf  = "steps:\n  - uses: docker://ghcr.io/org/img:latest\n"
        rep = v._verify_text(wf, "wf.yml")
        assert rep.total_actions == 0

    def test_local_path_skipped(self):
        v   = PinnedActionVerifier()
        wf  = "steps:\n  - uses: ./local-action\n"
        rep = v._verify_text(wf, "wf.yml")
        assert rep.total_actions == 0

    def test_no_pin_critical_severity(self):
        v   = PinnedActionVerifier()
        wf  = "steps:\n  - uses: actions/checkout\n"
        rep = v._verify_text(wf, "wf.yml")
        assert rep.findings[0].severity == "CRITICAL"

    def test_mutable_tag_high_severity(self):
        v   = PinnedActionVerifier()
        wf  = "steps:\n  - uses: actions/checkout@v3\n"
        rep = v._verify_text(wf, "wf.yml")
        assert rep.findings[0].severity == "HIGH"

    def test_verify_file(self, tmp_path):
        wf_file = tmp_path / "train.yml"
        wf_file.write_text(self.PINNED_WF)
        v   = PinnedActionVerifier()
        rep = v.verify_file(wf_file)
        assert rep.overall_pass

    def test_verify_directory(self, tmp_path):
        (tmp_path / "train.yml").write_text(self.PINNED_WF)
        (tmp_path / "deploy.yml").write_text(self.UNPINNED_WF)
        v   = PinnedActionVerifier()
        rep = v.verify_directory(tmp_path)
        assert rep.unpinned >= 2
        assert not rep.overall_pass


# ── BuildAttestationCapture ───────────────────────────────────────────────────

class TestBuildAttestation:

    def test_capture_returns_attestation(self):
        cap  = BuildAttestationCapture(env_var_allowlist=["PATH"])
        att  = cap.capture()
        assert att.build_id
        assert att.timestamp
        assert att.python_version
        assert att.platform_info

    def test_sha256_proof_valid(self):
        cap = BuildAttestationCapture(env_var_allowlist=["PATH"])
        att = cap.capture()
        assert att.verify_proof()

    def test_tampered_proof_invalid(self):
        cap = BuildAttestationCapture(env_var_allowlist=["PATH"])
        att = cap.capture()
        att.git_sha = "tampered"
        assert not att.verify_proof()

    def test_secrets_excluded(self):
        cap = BuildAttestationCapture()
        att = cap.capture()
        for k in att.env_vars:
            assert "password" not in k.lower()
            assert "secret"   not in k.lower()
            assert "token"    not in k.lower()

    def test_save_and_load(self, tmp_path):
        cap  = BuildAttestationCapture(env_var_allowlist=["PATH"])
        att  = cap.capture()
        path = tmp_path / "attestation.json"
        att.save(path)
        from build_attestation import BuildAttestation
        loaded = BuildAttestation.load(path)
        assert loaded.build_id    == att.build_id
        assert loaded.sha256_proof == att.sha256_proof
        assert loaded.verify_proof()


# ── ArtefactSigner ────────────────────────────────────────────────────────────

class TestArtefactSigner:

    def test_sign_and_verify_file(self, tmp_path):
        f       = tmp_path / "model.pt"
        f.write_bytes(os.urandom(1024))
        signer  = ArtefactSigner.from_new_keypair("ci-signer")
        sig     = signer.sign_file(f)
        assert sig.verify(sig.artefact_sha256)

    def test_wrong_digest_fails(self, tmp_path):
        f      = tmp_path / "model.pt"
        f.write_bytes(os.urandom(512))
        signer = ArtefactSigner.from_new_keypair()
        sig    = signer.sign_file(f)
        assert not sig.verify("wrong" * 16)

    def test_sign_digest_directly(self):
        signer = ArtefactSigner.from_new_keypair()
        sha256 = "a" * 64
        sig    = signer.sign_digest(sha256, name="model.bin")
        assert sig.verify(sha256)

    def test_save_sig_file(self, tmp_path):
        signer = ArtefactSigner.from_new_keypair()
        sig    = signer.sign_digest("b" * 64)
        path   = tmp_path / "model.pt.sig"
        sig.save_sig(path)
        assert path.exists()
        assert len(path.read_bytes()) == 64   # Ed25519 signature is 64 bytes

    def test_save_bundle_json(self, tmp_path):
        signer = ArtefactSigner.from_new_keypair()
        sig    = signer.sign_digest("c" * 64, name="model.bin")
        path   = tmp_path / "bundle.json"
        sig.save_bundle(path)
        d = json.loads(path.read_text())
        assert "base64Sig" in d
        assert "payload"   in d

    def test_signer_id_recorded(self):
        signer = ArtefactSigner.from_new_keypair(signer_id="github-actions-runner")
        sig    = signer.sign_digest("d" * 64)
        assert sig.signer_id == "github-actions-runner"
