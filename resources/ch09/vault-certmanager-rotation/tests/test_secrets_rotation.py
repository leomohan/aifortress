"""
tests/test_secrets_rotation.py
AI Fortress · Chapter 9 · Code Sample 9.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import datetime
import json
import pytest
from pathlib import Path

from credential_rotator import CredentialRotator, CredentialSpec, RotationError
from api_key_lifecycle import APIKeyLifecycleManager
from cert_renewal_tracker import CertRenewalTracker
from rotation_audit_trail import RotationAuditTrail


# ── CredentialRotator ─────────────────────────────────────────────────────────

class TestCredentialRotator:

    def _spec(self):
        return CredentialSpec(
            service="training-db", database="ml_data",
            username="ml_user", db_type="postgresql",
            host="db.example.com", port=5432,
        )

    def _rotator(self, smoke_ok=True, audit=None):
        created  = []
        revoked  = []
        stored   = []
        def create(spec, pw):  created.append(pw)
        def revoke(spec, pw):  revoked.append(pw)
        def smoke(spec, pw):   return smoke_ok
        def store(spec, pw):   stored.append(pw)
        rotator = CredentialRotator(
            create_cred_fn=create, revoke_cred_fn=revoke,
            smoke_test_fn=smoke, store_cred_fn=store,
            audit_trail=audit,
        )
        return rotator, created, revoked, stored

    def test_successful_rotation_returns_cert(self):
        r, created, revoked, stored = self._rotator()
        cert = r.rotate(self._spec(), old_password="old-pass-123")
        assert cert.service  == "training-db"
        assert cert.username == "ml_user"
        assert cert.sha256_proof
        assert len(created) == 1
        assert len(stored)  == 1
        assert "old-pass-123" in revoked

    def test_smoke_test_failure_raises(self):
        r, created, revoked, _ = self._rotator(smoke_ok=False)
        with pytest.raises(RotationError) as exc:
            r.rotate(self._spec(), old_password="old-pass")
        assert "smoke test" in str(exc.value).lower()

    def test_smoke_failure_reverts_new_cred(self):
        r, created, revoked, _ = self._rotator(smoke_ok=False)
        with pytest.raises(RotationError):
            r.rotate(self._spec(), old_password="old-pass")
        # New credential should be revoked on failure
        assert len(revoked) == 1
        assert revoked[0] != "old-pass"   # revoked the new, not the old

    def test_old_password_revoked_on_success(self):
        r, _, revoked, _ = self._rotator()
        r.rotate(self._spec(), old_password="old-pass-xyz")
        assert "old-pass-xyz" in revoked

    def test_cert_proof_valid(self):
        import hashlib
        import dataclasses
        r, _, _, _ = self._rotator()
        cert  = r.rotate(self._spec(), old_password="old")
        d     = dataclasses.asdict(cert)
        d.pop("sha256_proof")
        expected = hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()
        assert cert.sha256_proof == expected

    def test_connection_string_postgresql(self):
        spec = self._spec()
        cs   = CredentialRotator.connection_string(spec, "pw123")
        assert "postgresql://" in cs
        assert "ml_user:pw123" in cs

    def test_connection_string_mongodb(self):
        spec = CredentialSpec("svc", "mldb", "admin", "mongodb", "localhost", 27017)
        cs   = CredentialRotator.connection_string(spec, "pw")
        assert "mongodb://" in cs

    def test_audit_trail_logged(self, tmp_path):
        trail   = RotationAuditTrail(tmp_path / "trail.jsonl")
        r, _, _, _ = self._rotator(audit=trail)
        r.rotate(self._spec(), old_password="old")
        events = trail.read_events()
        assert len(events) == 1
        assert events[0].secret_type == "credential"


# ── APIKeyLifecycleManager ────────────────────────────────────────────────────

class TestAPIKeyLifecycleManager:

    def _mgr(self, tmp_path=None):
        path = (tmp_path / "keys.json") if tmp_path else None
        return APIKeyLifecycleManager(state_path=path)

    def test_register_and_list(self):
        mgr   = self._mgr()
        entry = mgr.register("huggingface", "HF token", "alice", "hf_xxx", ttl_days=90)
        keys  = mgr.list_keys()
        assert len(keys) == 1
        assert keys[0].service == "huggingface"

    def test_key_hash_stored_not_raw(self):
        mgr   = self._mgr()
        entry = mgr.register("openai", "GPT key", "bob", "sk_test_xxx")
        assert entry.key_hash != "sk_test_xxx"
        assert len(entry.key_hash) == 64   # SHA-256 hex

    def test_expiry_critical_alert(self):
        mgr = self._mgr()
        exp = (datetime.datetime.now(datetime.timezone.utc) +
               datetime.timedelta(hours=12)).isoformat()
        mgr._keys["k1"] = __import__("api_key_lifecycle").ExternalKeyEntry(
            key_id="k1", service="openai", name="gpt-key", owner="alice",
            created_at="2024-01-01", expires_at=exp, key_hash="a" * 64,
        )
        report = mgr.check_expiry()
        assert report.critical == 1
        assert report.alerts[0].severity == "CRITICAL"

    def test_expiry_warning_alert(self):
        mgr = self._mgr()
        exp = (datetime.datetime.now(datetime.timezone.utc) +
               datetime.timedelta(days=5)).isoformat()
        mgr._keys["k1"] = __import__("api_key_lifecycle").ExternalKeyEntry(
            key_id="k1", service="openai", name="gpt-key", owner="alice",
            created_at="2024-01-01", expires_at=exp, key_hash="b" * 64,
        )
        report = mgr.check_expiry()
        assert report.warning == 1

    def test_no_expiry_not_alerted(self):
        mgr   = self._mgr()
        mgr.register("aws", "IAM key", "carol", "AKIA...", ttl_days=None)
        report = mgr.check_expiry()
        assert report.no_expiry == 1
        assert report.critical == 0

    def test_ok_key_not_alerted(self):
        mgr = self._mgr()
        mgr.register("hf", "token", "dave", "hf_abc", ttl_days=90)
        report = mgr.check_expiry()
        assert report.ok == 1
        assert report.critical == 0

    def test_record_rotation_updates_hash(self):
        mgr   = self._mgr()
        entry = mgr.register("openai", "key", "eve", "sk_old", ttl_days=30)
        mgr.record_rotation(entry.key_id, "sk_new")
        updated = mgr.list_keys()[0]
        import hashlib
        assert updated.key_hash == hashlib.sha256("sk_new".encode()).hexdigest()
        assert updated.last_rotated != ""

    def test_deregister_removes_key(self):
        mgr   = self._mgr()
        entry = mgr.register("hf", "token", "frank", "abc", ttl_days=10)
        mgr.deregister(entry.key_id)
        assert len(mgr.list_keys()) == 0

    def test_persistence_across_instances(self, tmp_path):
        mgr1  = self._mgr(tmp_path)
        mgr1.register("hf", "token", "alice", "hf_abc", ttl_days=60)
        mgr2  = APIKeyLifecycleManager(state_path=tmp_path / "keys.json")
        assert len(mgr2.list_keys()) == 1

    def test_summary_string(self):
        mgr = self._mgr()
        exp = (datetime.datetime.now(datetime.timezone.utc) +
               datetime.timedelta(hours=1)).isoformat()
        mgr._keys["k1"] = __import__("api_key_lifecycle").ExternalKeyEntry(
            key_id="k1", service="openai", name="key", owner="alice",
            created_at="2024-01-01", expires_at=exp, key_hash="c" * 64,
        )
        report = mgr.check_expiry()
        assert "CRITICAL" in report.summary()


# ── CertRenewalTracker ────────────────────────────────────────────────────────

class TestCertRenewalTracker:

    def _now(self, delta_days=0):
        return (datetime.datetime.now(datetime.timezone.utc) +
                datetime.timedelta(days=delta_days))

    def test_ok_cert_no_alert(self):
        tracker = CertRenewalTracker()
        tracker.register_manual("model-server cert", "inference", "model-server.internal",
                                 expires_at=self._now(90).isoformat())
        report = tracker.check()
        assert report.ok == 1
        assert report.critical == 0

    def test_critical_cert_alert(self):
        tracker = CertRenewalTracker()
        tracker.register_manual("expiring cert", "inference", "host",
                                 expires_at=self._now(0).isoformat())
        report = tracker.check()
        assert report.critical == 1
        assert report.alerts[0].severity == "CRITICAL"

    def test_warning_cert_alert(self):
        tracker = CertRenewalTracker()
        tracker.register_manual("warning cert", "inference", "host",
                                 expires_at=self._now(5).isoformat())
        report = tracker.check()
        assert report.warning == 1

    def test_info_cert_alert(self):
        tracker = CertRenewalTracker()
        tracker.register_manual("info cert", "inference", "host",
                                 expires_at=self._now(20).isoformat())
        report = tracker.check()
        assert report.info == 1

    def test_auto_renew_acme(self):
        renewed_hosts = []
        def acme(hostname): renewed_hosts.append(hostname)
        tracker = CertRenewalTracker(acme_renew_fn=acme, auto_renew_days=7)
        tracker.register_manual("cert", "web", "ml.example.com",
                                 expires_at=self._now(3).isoformat(),
                                 renewal_method="acme")
        report  = tracker.check(auto_renew=True)
        assert len(report.renewed) == 1
        assert "ml.example.com" in renewed_hosts

    def test_auto_renew_spire(self):
        renewed_ids = []
        def spire(sid): renewed_ids.append(sid)
        tracker = CertRenewalTracker(spire_renew_fn=spire, auto_renew_days=7)
        tracker.register_manual("svid", "inference", "host",
                                 expires_at=self._now(2).isoformat(),
                                 renewal_method="spire",
                                 spiffe_id="spiffe://example.com/workload")
        report = tracker.check(auto_renew=True)
        assert len(report.renewed) == 1
        assert "spiffe://example.com/workload" in renewed_ids

    def test_register_from_pem(self):
        from workload_identity_verifier import WorkloadIdentityVerifier
        cert_pem, _, _, _, _ = WorkloadIdentityVerifier.generate_test_svid(
            "ml-platform.example.com", "ns/inference/sa/server")
        tracker = CertRenewalTracker()
        entry   = tracker.register_pem(cert_pem, "test svid", "inference")
        assert entry.cert_id
        assert entry.spiffe_id.startswith("spiffe://")

    def test_save_json(self, tmp_path):
        tracker = CertRenewalTracker()
        tracker.register_manual("cert", "svc", "host",
                                 expires_at=self._now(3).isoformat())
        report = tracker.check()
        path   = tmp_path / "renewal.json"
        report.save_json(path)
        data = json.loads(path.read_text())
        assert "alerts" in data


# ── RotationAuditTrail ────────────────────────────────────────────────────────

class TestRotationAuditTrail:

    def test_log_and_read(self, tmp_path):
        trail = RotationAuditTrail(tmp_path / "trail.jsonl")
        trail.log_rotation("training-db", "credential", detail="Rotated ml_user", success=True)
        events = trail.read_events()
        assert len(events) == 1
        assert events[0].event_type  == "credential_rotated"
        assert events[0].service     == "training-db"

    def test_log_failure(self, tmp_path):
        trail = RotationAuditTrail(tmp_path / "trail.jsonl")
        trail.log_rotation("training-db", "credential", detail="Smoke test failed", success=False)
        events = trail.read_events()
        assert events[0].event_type == "credential_failed"

    def test_expiry_alert_logged(self, tmp_path):
        trail = RotationAuditTrail(tmp_path / "trail.jsonl")
        trail.log_expiry_alert("inference", "certificate", "Expires in 3 days", "CRITICAL")
        events = trail.read_events()
        assert events[0].event_type == "certificate_expiry"
        assert events[0].metadata["severity"] == "CRITICAL"

    def test_scheduled_event_logged(self, tmp_path):
        trail = RotationAuditTrail(tmp_path / "trail.jsonl")
        trail.log_scheduled("feature-store", "api_key", "2025-06-01T00:00:00Z")
        events = trail.read_events()
        assert events[0].event_type == "rotation_scheduled"

    def test_chain_valid(self, tmp_path):
        trail = RotationAuditTrail(tmp_path / "trail.jsonl")
        for i in range(5):
            trail.log_rotation(f"svc-{i}", "credential", success=True)
        assert trail.verify_chain()

    def test_chain_invalid_after_tamper(self, tmp_path):
        path  = tmp_path / "trail.jsonl"
        trail = RotationAuditTrail(path)
        trail.log_rotation("svc-a", "credential", success=True)
        trail.log_rotation("svc-b", "credential", success=True)
        lines = path.read_text().splitlines()
        first = json.loads(lines[0])
        first["service"] = "hacked"
        lines[0] = json.dumps(first)
        path.write_text("\n".join(lines) + "\n")
        assert not trail.verify_chain()

    def test_chain_continues_across_instances(self, tmp_path):
        path   = tmp_path / "trail.jsonl"
        trail1 = RotationAuditTrail(path)
        trail1.log_rotation("svc-a", "credential")
        trail2 = RotationAuditTrail(path)
        trail2.log_rotation("svc-b", "api_key")
        assert trail2.verify_chain()

    def test_multiple_event_types_in_log(self, tmp_path):
        trail = RotationAuditTrail(tmp_path / "trail.jsonl")
        trail.log_rotation("db", "credential")
        trail.log_expiry_alert("api", "api_key", "expires soon", "WARNING")
        trail.log_scheduled("cert-mgr", "certificate", "2025-07-01")
        events = trail.read_events()
        types  = {e.event_type for e in events}
        assert "credential_rotated" in types
        assert "api_key_expiry"     in types
        assert "rotation_scheduled" in types
