"""
tests/test_secure_training.py  —  Secure training environment tests
AI Fortress · Chapter 4 · Code Sample 4.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import logging
import os
import tempfile
from pathlib import Path
import pytest

from secrets_manager import SecretStr, SecretScrubFilter, SecretsManager, install_global_scrub_filter
from network_isolation import NetworkPolicy, NetworkPolicyGenerator, AllowedEndpoint, EgressAuditVerifier
from gpu_hygiene import GPUHygieneManager
from workspace_manager import WorkspaceManager, ephemeral_workspace
from reproducibility_lock import ReproducibilityLock, EnvironmentDriftError


class TestSecretStr:
    def test_repr_redacted(self):
        s = SecretStr("my-super-secret")
        assert "my-super-secret" not in repr(s)
        assert "**" in repr(s)

    def test_str_redacted(self):
        s = SecretStr("my-super-secret")
        assert "my-super-secret" not in str(s)

    def test_get_secret_value(self):
        s = SecretStr("my-super-secret")
        assert s.get_secret_value() == "my-super-secret"

    def test_equality(self):
        a = SecretStr("abc")
        b = SecretStr("abc")
        c = SecretStr("xyz")
        assert a == b
        assert a != c


class TestSecretScrubFilter:
    def test_scrubs_password_in_log(self):
        filt = SecretScrubFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "password=abc123", (), None)
        filt.filter(record)
        assert "abc123" not in record.msg
        assert "[REDACTED]" in record.msg

    def test_scrubs_literal_secret(self):
        filt = SecretScrubFilter()
        filt.add_literal("tok_verysecret")
        record = logging.LogRecord("test", logging.INFO, "", 0,
                                   "Connecting with tok_verysecret to API", (), None)
        filt.filter(record)
        assert "tok_verysecret" not in record.msg

    def test_clean_log_passes_through(self):
        filt = SecretScrubFilter()
        msg = "Training epoch 1, loss=0.342"
        record = logging.LogRecord("test", logging.INFO, "", 0, msg, (), None)
        filt.filter(record)
        assert record.msg == msg


class TestSecretsManager:
    def test_env_backend_retrieves_secret(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET_KEY", "supersecretvalue")
        sm  = SecretsManager(backend="env")
        val = sm.get("MY_SECRET_KEY")
        assert isinstance(val, SecretStr)
        assert val.get_secret_value() == "supersecretvalue"

    def test_missing_secret_raises(self, monkeypatch):
        monkeypatch.delenv("NONEXISTENT_VAR", raising=False)
        sm = SecretsManager(backend="env")
        with pytest.raises(KeyError):
            sm.get("NONEXISTENT_VAR")

    def test_unknown_backend_raises(self):
        with pytest.raises(ValueError, match="Unknown backend"):
            SecretsManager(backend="bogus")


class TestNetworkPolicyGenerator:
    def _make_policy(self):
        pol = NetworkPolicy(job_id="test-job-001")
        pol.add("s3.amazonaws.com", 443, description="S3")
        pol.add("api.wandb.ai",     443, description="W&B")
        return pol

    def test_iptables_rules_structure(self):
        gen   = NetworkPolicyGenerator()
        rules = gen.iptables_rules(self._make_policy())
        assert "OUTPUT DROP" in rules
        assert "s3.amazonaws.com" in rules
        assert "api.wandb.ai"     in rules
        assert "COMMIT"           in rules

    def test_nftables_rules_structure(self):
        gen   = NetworkPolicyGenerator()
        rules = gen.nftables_rules(self._make_policy())
        assert "policy drop" in rules
        assert "s3.amazonaws.com" in rules

    def test_kubernetes_network_policy(self):
        gen      = NetworkPolicyGenerator()
        manifest = gen.kubernetes_network_policy(self._make_policy(), namespace="ml")
        assert manifest["kind"] == "NetworkPolicy"
        assert manifest["metadata"]["namespace"] == "ml"
        assert len(manifest["spec"]["egress"]) >= 2   # DNS + endpoints

    def test_egress_audit_verifier(self):
        pol = self._make_policy()
        verifier = EgressAuditVerifier(pol)
        logs = [
            "kernel: [AI-FORTRESS-BLOCKED] IN= OUT=eth0 DST=10.20.30.40 DPT=8080",
            "kernel: [AI-FORTRESS-BLOCKED] IN= OUT=eth0 DST=1.2.3.4 DPT=443",
            "Normal syslog line unrelated to training",
        ]
        blocked = verifier.verify_log(logs)
        assert len(blocked) == 2
        assert blocked[0]["port"] == 8080


class TestGPUHygieneManager:
    def test_no_torch_returns_unknown_vram(self):
        mgr = GPUHygieneManager(job_id="test-001")
        # Without GPU/torch available, should not raise
        cert = mgr.cleanup()
        assert cert.job_id == "test-001"
        assert cert.cleanup_method in ("no_op_torch_unavailable", "torch_zero_empty_cache_synchronize")
        assert len(cert.sha256_proof) == 64

    def test_pre_job_check_no_torch(self):
        mgr    = GPUHygieneManager(job_id="test-002")
        report = mgr.pre_job_check()
        assert "status" in report
        assert report["status"] in ("clean", "unknown")

    def test_certificate_tamper_evidence(self):
        mgr  = GPUHygieneManager(job_id="test-003")
        cert = mgr.cleanup()
        import hashlib, json
        fields  = cert.to_dict()
        payload = json.dumps({k: v for k, v in fields.items() if k != "sha256_proof"}, sort_keys=True)
        expected = hashlib.sha256(payload.encode()).hexdigest()
        assert cert.sha256_proof == expected


class TestWorkspaceManager:
    def test_creates_and_wipes_workspace(self, tmp_path):
        ws_path_ref = []
        with WorkspaceManager(job_id="test-ws", base_dir=str(tmp_path), n_wipe_passes=1) as ws:
            assert ws.path.exists()
            assert (ws.path / "data").exists()
            # Write a file
            test_file = ws.path / "data" / "secret.txt"
            test_file.write_text("sensitive model weights")
            ws_path_ref.append(ws.path)

        # After exit, workspace must not exist
        assert not ws_path_ref[0].exists()

    def test_workspace_mode_700(self, tmp_path):
        with WorkspaceManager(job_id="test-perms", base_dir=str(tmp_path), n_wipe_passes=0) as ws:
            mode = oct(ws.path.stat().st_mode & 0o777)
            assert mode == oct(0o700)

    def test_ephemeral_workspace_context(self, tmp_path):
        with ephemeral_workspace(job_id="test-eph", base_dir=str(tmp_path), n_wipe_passes=0) as ws:
            p = ws.path
            assert p.exists()
        assert not p.exists()


class TestReproducibilityLock:
    def test_capture_and_verify_same_env(self, tmp_path):
        lock     = ReproducibilityLock.capture(seeds={"numpy": 42})
        lock_path = tmp_path / "env.lock.json"
        lock.save(lock_path)
        loaded   = ReproducibilityLock.load(lock_path)
        # Verify against itself — should pass
        ReproducibilityLock.verify(loaded)

    def test_tamper_raises_drift_error(self, tmp_path):
        lock     = ReproducibilityLock.capture()
        lock_path = tmp_path / "env.lock.json"
        lock.save(lock_path)
        # Tamper with the lock file
        data = json.loads(lock_path.read_text())
        data["python_version"] = "0.0.0"
        lock_path.write_text(json.dumps(data))
        loaded = ReproducibilityLock.load(lock_path)
        with pytest.raises(EnvironmentDriftError):
            ReproducibilityLock.verify(loaded)

    def test_lock_has_sha256(self):
        lock = ReproducibilityLock.capture()
        assert len(lock.sha256) == 64
