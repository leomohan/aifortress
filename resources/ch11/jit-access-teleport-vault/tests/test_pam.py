"""
tests/test_pam.py
AI Fortress · Chapter 11 · Code Sample 11.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import time
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from jit_access import JITAccessManager
from credential_checkout import CredentialCheckoutManager
from session_recorder import SessionRecorder
from pam_audit_trail import PAMAuditTrail


# ── JITAccessManager ──────────────────────────────────────────────────────────

class TestJITAccessManager:

    def _mgr(self, auto_approve=False, audit=None):
        fn = (lambda req: True) if auto_approve else None
        return JITAccessManager(auto_approve_fn=fn, audit_path=audit)

    def test_request_created(self):
        mgr = self._mgr()
        req = mgr.request_access("alice", "model:promote", "fraud-model-v3",
                                  "Emergency production deployment for incident fix")
        assert req.status == "pending"
        assert req.principal == "alice"

    def test_invalid_operation_raises(self):
        mgr = self._mgr()
        with pytest.raises(ValueError, match="not a recognised"):
            mgr.request_access("alice", "superpower:use", "resource",
                               "some justification here")

    def test_short_justification_raises(self):
        mgr = self._mgr()
        with pytest.raises(ValueError, match="Justification"):
            mgr.request_access("alice", "model:promote", "resource", "short")

    def test_approve_pending_request(self):
        mgr = self._mgr()
        req = mgr.request_access("bob", "registry:admin", "*",
                                  "Need to clean up stale model versions from registry")
        dec = mgr.approve(req.request_id, approver="security-team")
        assert dec.approved
        assert mgr._requests[req.request_id].status == "approved"

    def test_deny_pending_request(self):
        mgr = self._mgr()
        req = mgr.request_access("carol", "cluster:admin", "*",
                                  "Need to scale down GPU cluster for cost savings")
        dec = mgr.deny(req.request_id, approver="security-team",
                       reason="No emergency — follow normal process")
        assert not dec.approved

    def test_activate_approved_request(self):
        mgr = self._mgr()
        req = mgr.request_access("dave", "model:promote", "nlp-model-v2",
                                  "Scheduled promotion approved by ML team lead")
        mgr.approve(req.request_id, approver="mlops-lead")
        active_req = mgr.activate(req.request_id)
        assert active_req.status   == "active"
        assert active_req.expires_at != ""

    def test_activate_not_approved_raises(self):
        mgr = self._mgr()
        req = mgr.request_access("eve", "data:admin", "training-data",
                                  "Need to backfill missing labels in dataset partition")
        with pytest.raises(ValueError):
            mgr.activate(req.request_id)

    def test_check_access_active_grant(self):
        mgr = self._mgr()
        req = mgr.request_access("frank", "model:promote", "*",
                                  "Automated canary promotion triggered by CI pipeline")
        mgr.approve(req.request_id, "admin")
        mgr.activate(req.request_id)
        assert mgr.check_access("frank", "model:promote")

    def test_check_access_expired(self):
        mgr = self._mgr()
        req = mgr.request_access("grace", "model:promote", "*",
                                  "Short-lived test promotion to verify new model")
        mgr.approve(req.request_id, "admin")
        mgr.activate(req.request_id)
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        assert not mgr.check_access("grace", "model:promote", now=future)

    def test_revoke_active_session(self):
        mgr = self._mgr()
        req = mgr.request_access("harry", "cluster:admin", "*",
                                  "Emergency scale-up required for training job failure")
        mgr.approve(req.request_id, "admin")
        mgr.activate(req.request_id)
        assert mgr.revoke(req.request_id, revoked_by="security-team")
        assert not mgr.check_access("harry", "cluster:admin")

    def test_auto_approve(self):
        mgr = self._mgr(auto_approve=True)
        req = mgr.request_access("ivan", "pipeline:override", "*",
                                  "Pre-approved emergency pipeline bypass via runbook")
        assert req.status == "approved"

    def test_pending_requests_list(self):
        mgr = self._mgr()
        mgr.request_access("alice", "model:promote", "*",
                            "Pending model promotion request awaiting approval")
        mgr.request_access("bob",   "data:admin",    "*",
                            "Pending data admin request for dataset backfill")
        assert len(mgr.pending_requests()) == 2

    def test_audit_log_events(self, tmp_path):
        log = tmp_path / "jit.jsonl"
        mgr = self._mgr(audit=log)
        req = mgr.request_access("alice", "model:promote", "*",
                                  "Promotion request for audit log test scenario")
        mgr.approve(req.request_id, "admin")
        events = {json.loads(l)["event"] for l in log.read_text().splitlines() if l}
        assert "jit_requested" in events
        assert "jit_approved"  in events


# ── CredentialCheckoutManager ─────────────────────────────────────────────────

class TestCredentialCheckoutManager:

    def test_register_and_checkout(self):
        mgr     = CredentialCheckoutManager()
        rec     = mgr.register("prod-db-admin", "super-secret-password-123")
        receipt = mgr.checkout(rec.cred_id, "alice", "session-001")
        assert receipt.principal   == "alice"
        assert receipt.session_id  == "session-001"
        assert receipt.cred_name   == "prod-db-admin"

    def test_exclusive_checkout_blocks_second(self):
        mgr = CredentialCheckoutManager()
        rec = mgr.register("registry-key", "signing-key-value")
        mgr.checkout(rec.cred_id, "alice", "sess-1", ttl_seconds=3600)
        with pytest.raises(PermissionError, match="already checked out"):
            mgr.checkout(rec.cred_id, "bob", "sess-2")

    def test_checkin_releases_credential(self):
        mgr = CredentialCheckoutManager()
        rec = mgr.register("cluster-root", "root-key-value")
        mgr.checkout(rec.cred_id, "alice", "sess-1")
        res = mgr.checkin(rec.cred_id, "sess-1")
        assert res.success
        assert mgr.is_available(rec.cred_id)

    def test_wrong_session_checkin_fails(self):
        mgr = CredentialCheckoutManager()
        rec = mgr.register("db-cred", "password")
        mgr.checkout(rec.cred_id, "alice", "sess-alice")
        res = mgr.checkin(rec.cred_id, "sess-bob")
        assert not res.success
        assert "mismatch" in res.reason.lower()

    def test_expired_checkout_auto_released(self):
        mgr = CredentialCheckoutManager()
        rec = mgr.register("temp-cred", "value")
        mgr.checkout(rec.cred_id, "alice", "sess-1", ttl_seconds=1)
        time.sleep(0.01)
        # Sweep after TTL
        future = datetime.now(timezone.utc) + timedelta(seconds=5)
        # Simulate by direct check via is_available with internal sweep
        cred = mgr._creds[rec.cred_id]
        from datetime import timedelta as td
        cred.expires_at = (datetime.now(timezone.utc) - td(seconds=1)).isoformat()
        assert mgr.is_available(rec.cred_id)

    def test_sweep_expired(self):
        mgr = CredentialCheckoutManager()
        rec = mgr.register("cred", "value")
        cred = mgr._creds[rec.cred_id]
        cred.checked_out    = True
        cred.session_id     = "sess"
        cred.expires_at     = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        released = mgr.sweep_expired()
        assert released == 1
        assert not cred.checked_out

    def test_audit_log_events(self, tmp_path):
        log = tmp_path / "checkout.jsonl"
        mgr = CredentialCheckoutManager(audit_path=log)
        rec = mgr.register("cred", "value")
        mgr.checkout(rec.cred_id, "alice", "sess-1")
        mgr.checkin(rec.cred_id, "sess-1")
        events = {json.loads(l)["event"] for l in log.read_text().splitlines() if l}
        assert "credential_checked_out" in events
        assert "credential_checked_in"  in events

    def test_credential_hash_not_stored_as_plaintext(self):
        mgr = CredentialCheckoutManager()
        rec = mgr.register("secret-cred", "plaintext-password-here")
        assert rec.cred_hash != "plaintext-password-here"
        assert len(rec.cred_hash) == 64


# ── SessionRecorder ───────────────────────────────────────────────────────────

class TestSessionRecorder:

    def test_start_session(self):
        rec = SessionRecorder()
        s   = rec.start("alice", "model:promote", "fraud-v3", "req-001", "admin")
        assert s.session_id
        assert s.started_at
        assert not s.ended_at

    def test_record_commands(self):
        rec = SessionRecorder()
        s   = rec.start("bob", "cluster:admin", "gpu-cluster", "req-002", "admin")
        rec.record_command(s.session_id, "kubectl scale --replicas=4")
        rec.record_command(s.session_id, "kubectl get pods")
        session = rec.get(s.session_id)
        assert len(session.commands) == 2

    def test_close_sets_hash(self):
        rec = SessionRecorder()
        s   = rec.start("carol", "registry:admin", "model-registry", "req-003", "admin")
        closed = rec.close(s.session_id, termination="normal")
        assert closed.ended_at
        assert closed.record_hash
        assert len(closed.record_hash) == 64

    def test_close_sets_duration(self):
        rec = SessionRecorder()
        s   = rec.start("dave", "data:admin", "train-data", "req-004", "admin")
        time.sleep(0.05)
        closed = rec.close(s.session_id)
        assert closed.duration_secs > 0

    def test_active_sessions(self):
        rec = SessionRecorder()
        s1  = rec.start("alice", "model:promote", "m1", "r1", "admin")
        s2  = rec.start("bob",   "cluster:admin", "c1", "r2", "admin")
        rec.close(s1.session_id)
        active = rec.active_sessions()
        assert len(active) == 1
        assert active[0].session_id == s2.session_id

    def test_session_persisted_to_file(self, tmp_path):
        path = tmp_path / "sessions.jsonl"
        rec  = SessionRecorder(sessions_path=path)
        s    = rec.start("eve", "pipeline:override", "deploy-pipeline", "r5", "admin")
        rec.close(s.session_id)
        lines = path.read_text().splitlines()
        assert len(lines) == 1
        data  = json.loads(lines[0])
        assert data["principal"] == "eve"
        assert data["record_hash"]

    def test_close_nonexistent_returns_none(self):
        rec    = SessionRecorder()
        result = rec.close("nonexistent-session-id")
        assert result is None


# ── PAMAuditTrail ─────────────────────────────────────────────────────────────

class TestPAMAuditTrail:

    def test_log_and_read(self, tmp_path):
        trail = PAMAuditTrail(tmp_path / "pam.jsonl")
        ev    = trail.log("jit_approved", "alice", "model:promote", "fraud-v3",
                          "Approved by security team")
        events = trail.read_events()
        assert len(events) == 1
        assert events[0].event_type == "jit_approved"
        assert events[0].principal  == "alice"

    def test_chain_valid(self, tmp_path):
        trail = PAMAuditTrail(tmp_path / "pam.jsonl")
        for i in range(5):
            trail.log("jit_requested", f"user{i}", "model:promote")
        assert trail.verify_chain()

    def test_chain_invalid_after_tamper(self, tmp_path):
        path  = tmp_path / "pam.jsonl"
        trail = PAMAuditTrail(path)
        trail.log("jit_approved", "alice", "model:promote")
        trail.log("jit_activated", "alice", "model:promote")
        lines = path.read_text().splitlines()
        first = json.loads(lines[0])
        first["principal"] = "hacked"
        lines[0] = json.dumps(first)
        path.write_text("\n".join(lines) + "\n")
        assert not trail.verify_chain()

    def test_multiple_event_types(self, tmp_path):
        trail = PAMAuditTrail(tmp_path / "pam.jsonl")
        trail.log("jit_requested",        "alice", "model:promote")
        trail.log("credential_checked_out","bob",  "registry:admin")
        trail.log("session_closed",       "carol", "cluster:admin")
        events = trail.read_events()
        types  = {e.event_type for e in events}
        assert len(types) == 3

    def test_success_flag_recorded(self, tmp_path):
        trail = PAMAuditTrail(tmp_path / "pam.jsonl")
        trail.log("access_denied", "mallory", "secrets:admin", success=False)
        events = trail.read_events()
        assert not events[0].success

    def test_chain_continues_across_instances(self, tmp_path):
        path   = tmp_path / "pam.jsonl"
        trail1 = PAMAuditTrail(path)
        trail1.log("jit_approved", "alice", "model:promote")
        trail2 = PAMAuditTrail(path)
        trail2.log("jit_activated", "alice", "model:promote")
        assert trail2.verify_chain()
