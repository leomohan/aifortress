"""
tests/test_api_gateway.py
AI Fortress · Chapter 9 · Code Sample 9.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import hashlib
import hmac
import json
import time
import pytest
from pathlib import Path

from jwt_authenticator import JWTAuthenticator
from api_key_manager import APIKeyManager
from request_signing_verifier import RequestSigningVerifier
from ip_policy_enforcer import IPPolicyEnforcer
from security_audit_logger import SecurityAuditLogger


SECRET = b"super-secret-key-for-testing-32b"
AUD    = "ml-api"
ISS    = "auth.example.com"


# ── JWTAuthenticator ──────────────────────────────────────────────────────────

class TestJWTAuthenticator:

    def _auth(self, **kwargs):
        return JWTAuthenticator(SECRET, AUD, ISS, **kwargs)

    def _token(self, sub="user1", scope="predict:read", ttl=3600):
        return JWTAuthenticator.build_hs256_token(SECRET, sub, AUD, ISS, scope=scope, ttl=ttl)

    def test_valid_token_authenticates(self):
        result = self._auth().authenticate(self._token())
        assert result.authenticated
        assert result.principal == "user1"
        assert result.reason == "OK"

    def test_expired_token_rejected(self):
        token  = JWTAuthenticator.build_hs256_token(SECRET, "u", AUD, ISS, ttl=-1)
        result = self._auth().authenticate(token)
        assert not result.authenticated
        assert "expired" in result.reason.lower()

    def test_wrong_secret_rejected(self):
        token  = JWTAuthenticator.build_hs256_token(b"wrong-secret", "u", AUD, ISS)
        result = self._auth().authenticate(token)
        assert not result.authenticated
        assert "signature" in result.reason.lower()

    def test_wrong_audience_rejected(self):
        token  = JWTAuthenticator.build_hs256_token(SECRET, "u", "other-api", ISS)
        result = self._auth().authenticate(token)
        assert not result.authenticated
        assert "audience" in result.reason.lower()

    def test_wrong_issuer_rejected(self):
        token  = JWTAuthenticator.build_hs256_token(SECRET, "u", AUD, "evil.example.com")
        result = self._auth().authenticate(token)
        assert not result.authenticated

    def test_scope_enforced(self):
        token  = self._token(scope="read:data")
        result = self._auth(required_scopes={"predict:read"}).authenticate(token)
        assert not result.authenticated
        assert "scope" in result.reason.lower()

    def test_scope_satisfied(self):
        token  = self._token(scope="predict:read read:data")
        result = self._auth(required_scopes={"predict:read"}).authenticate(token)
        assert result.authenticated
        assert "predict:read" in result.scopes

    def test_malformed_token_rejected(self):
        result = self._auth().authenticate("not.a.jwt")
        assert not result.authenticated

    def test_alg_none_rejected(self):
        import base64
        h = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(b'{"sub":"x","aud":"ml-api","iss":"auth.example.com","exp":9999999999}').rstrip(b"=").decode()
        token = f"{h}.{p}."
        result = self._auth().authenticate(token)
        assert not result.authenticated

    def test_algorithm_not_in_allowlist_raises(self):
        with pytest.raises(ValueError):
            JWTAuthenticator(SECRET, AUD, ISS, algorithm="HS512")


# ── APIKeyManager ─────────────────────────────────────────────────────────────

class TestAPIKeyManager:

    def _mgr(self, audit=None):
        return APIKeyManager(hmac_secret=SECRET, audit_path=audit)

    def test_create_and_verify(self):
        mgr = self._mgr()
        key = mgr.create_key("alice", ["predict"])
        res = mgr.verify(key)
        assert res.valid
        assert res.owner == "alice"
        assert "predict" in res.scopes

    def test_wrong_key_not_valid(self):
        mgr = self._mgr()
        mgr.create_key("alice", ["predict"])
        res = mgr.verify("aif_wrongkey")
        assert not res.valid

    def test_revoked_key_rejected(self):
        mgr = self._mgr()
        key = mgr.create_key("bob", ["read"])
        mgr.revoke_key(key, reason="test revocation")
        res = mgr.verify(key)
        assert not res.valid
        assert "revoked" in res.reason.lower()

    def test_expired_key_rejected(self):
        mgr = self._mgr()
        key = mgr.create_key("carol", ["read"], ttl_days=0)
        # ttl_days=0 → expires right away (effectively expired)
        # force expiry by creating with -1 day
        # Instead: create key then manually set expiry to past
        from datetime import datetime, timezone, timedelta
        key_hash = mgr._hash(key)
        mgr._store[key_hash].expires_at = (
            datetime.now(timezone.utc) - timedelta(days=1)
        ).isoformat()
        res = mgr.verify(key)
        assert not res.valid
        assert "expired" in res.reason.lower()

    def test_rotate_produces_new_key(self):
        mgr     = self._mgr()
        old_key = mgr.create_key("dave", ["predict"])
        new_key = mgr.rotate_key(old_key)
        assert new_key != old_key
        assert new_key.startswith("aif_")
        res = mgr.verify(new_key)
        assert res.valid

    def test_rotate_unknown_key_raises(self):
        mgr = self._mgr()
        with pytest.raises(KeyError):
            mgr.rotate_key("aif_doesnotexist")

    def test_audit_log_written(self, tmp_path):
        log = tmp_path / "audit.jsonl"
        mgr = self._mgr(audit=log)
        key = mgr.create_key("eve", ["predict"])
        mgr.verify(key)
        lines = log.read_text().splitlines()
        events = [json.loads(l)["event"] for l in lines if l]
        assert "key_created" in events
        assert "key_used"    in events

    def test_invalid_prefix_rejected(self):
        mgr = self._mgr()
        res = mgr.verify("sk_notanafkey")
        assert not res.valid


# ── RequestSigningVerifier ────────────────────────────────────────────────────

class TestRequestSigningVerifier:

    KEY_ID = "svc-key-1"
    KEY    = b"signing-secret-32bytes-padded!!"

    def _verifier(self):
        return RequestSigningVerifier({self.KEY_ID: self.KEY})

    def _headers(self, method="POST", path="/v1/predict", body=b"", ts=None):
        return RequestSigningVerifier.sign_request(
            self.KEY, self.KEY_ID, method, path, body, timestamp=ts or int(time.time())
        )

    def test_valid_signature_passes(self):
        v = self._verifier()
        h = self._headers()
        res = v.verify("POST", "/v1/predict", h["X-AF-Timestamp"],
                       h["X-AF-Signature"], body=b"", key_id=h["X-AF-Key-Id"])
        assert res.valid
        assert res.reason == "OK"

    def test_tampered_body_fails(self):
        v = self._verifier()
        h = self._headers(body=b"original")
        res = v.verify("POST", "/v1/predict", h["X-AF-Timestamp"],
                       h["X-AF-Signature"], body=b"tampered", key_id=h["X-AF-Key-Id"])
        assert not res.valid

    def test_stale_timestamp_fails(self):
        v  = self._verifier()
        ts = int(time.time()) - 400   # 400s ago — outside 300s window
        h  = self._headers(ts=ts)
        res = v.verify("POST", "/v1/predict", h["X-AF-Timestamp"],
                       h["X-AF-Signature"], key_id=h["X-AF-Key-Id"], now=int(time.time()))
        assert not res.valid
        assert "replay" in res.reason.lower()

    def test_unknown_key_id_fails(self):
        v  = self._verifier()
        h  = self._headers()
        res = v.verify("POST", "/v1/predict", h["X-AF-Timestamp"],
                       h["X-AF-Signature"], key_id="unknown-key")
        assert not res.valid

    def test_wrong_method_fails(self):
        v = self._verifier()
        h = self._headers(method="POST")
        res = v.verify("GET", "/v1/predict", h["X-AF-Timestamp"],
                       h["X-AF-Signature"], key_id=h["X-AF-Key-Id"])
        assert not res.valid

    def test_body_included_in_signature(self):
        v    = self._verifier()
        body = b'{"input": "test data"}'
        h    = self._headers(body=body)
        res  = v.verify("POST", "/v1/predict", h["X-AF-Timestamp"],
                        h["X-AF-Signature"], body=body, key_id=h["X-AF-Key-Id"])
        assert res.valid


# ── IPPolicyEnforcer ──────────────────────────────────────────────────────────

class TestIPPolicyEnforcer:

    def test_default_allow_permits_any(self):
        enforcer = IPPolicyEnforcer(default_deny=False)
        dec = enforcer.evaluate("1.2.3.4", "/v1/predict")
        assert dec.allowed
        assert dec.reason == "default_allow"

    def test_default_deny_blocks_unknown(self):
        enforcer = IPPolicyEnforcer(default_deny=True)
        dec = enforcer.evaluate("1.2.3.4", "/v1/predict")
        assert not dec.allowed
        assert dec.reason == "default_deny"

    def test_allowlist_permits_matching_ip(self):
        enforcer = IPPolicyEnforcer(default_deny=True)
        enforcer.add_allowlist("/v1/predict", ["10.0.0.0/8"])
        dec = enforcer.evaluate("10.1.2.3", "/v1/predict")
        assert dec.allowed
        assert dec.reason == "allowlist_match"

    def test_allowlist_blocks_non_matching(self):
        enforcer = IPPolicyEnforcer(default_deny=True)
        enforcer.add_allowlist("/v1/predict", ["10.0.0.0/8"])
        dec = enforcer.evaluate("192.168.1.1", "/v1/predict")
        assert not dec.allowed

    def test_denylist_always_blocks(self):
        enforcer = IPPolicyEnforcer(global_denylist=["192.168.0.0/16"], default_deny=False)
        dec = enforcer.evaluate("192.168.1.5", "/v1/predict")
        assert not dec.allowed
        assert dec.reason == "denylist_match"

    def test_denylist_overrides_allowlist(self):
        enforcer = IPPolicyEnforcer(global_denylist=["10.0.0.0/8"])
        enforcer.add_allowlist("/v1/predict", ["10.0.0.0/8"])
        dec = enforcer.evaluate("10.1.2.3", "/v1/predict")
        assert not dec.allowed
        assert dec.reason == "denylist_match"

    def test_ipv6_supported(self):
        enforcer = IPPolicyEnforcer(global_denylist=["::1/128"])
        dec = enforcer.evaluate("::1", "/v1/predict")
        assert not dec.allowed

    def test_invalid_ip_rejected(self):
        enforcer = IPPolicyEnforcer()
        dec = enforcer.evaluate("not.an.ip", "/v1/predict")
        assert not dec.allowed
        assert dec.reason == "invalid_ip"

    def test_audit_log_on_deny(self, tmp_path):
        log      = tmp_path / "ip.jsonl"
        enforcer = IPPolicyEnforcer(global_denylist=["1.2.3.0/24"], audit_path=log)
        enforcer.evaluate("1.2.3.4")
        lines = log.read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["allowed"] is False


# ── SecurityAuditLogger ───────────────────────────────────────────────────────

class TestSecurityAuditLogger:

    def test_log_auth_success(self, tmp_path):
        logger = SecurityAuditLogger(tmp_path / "audit.jsonl")
        ev     = logger.log_auth_success("alice", "/v1/predict", "10.0.0.1", ["predict"])
        assert ev.event_type == "auth_success"
        assert ev.principal  == "alice"

    def test_log_auth_failure(self, tmp_path):
        logger = SecurityAuditLogger(tmp_path / "audit.jsonl")
        ev     = logger.log_auth_failure("", "/v1/predict", "1.2.3.4", "Bad token")
        assert ev.event_type == "auth_failure"
        assert ev.result     == "failure"

    def test_log_ip_deny(self, tmp_path):
        logger = SecurityAuditLogger(tmp_path / "audit.jsonl")
        ev     = logger.log_ip_deny("5.5.5.5", "/v1/predict", "denylist_match", "5.0.0.0/8")
        assert ev.event_type == "ip_deny"
        assert ev.result     == "deny"

    def test_events_persisted_and_readable(self, tmp_path):
        logger = SecurityAuditLogger(tmp_path / "audit.jsonl")
        logger.log_auth_success("alice", "/predict", "10.0.0.1")
        logger.log_auth_failure("", "/predict", "2.2.2.2", "bad sig")
        events = logger.read_events()
        assert len(events) == 2
        types  = [e.event_type for e in events]
        assert "auth_success" in types
        assert "auth_failure" in types

    def test_chain_valid_after_multiple_events(self, tmp_path):
        logger = SecurityAuditLogger(tmp_path / "audit.jsonl")
        for i in range(5):
            logger.log_auth_success(f"user{i}", "/predict", "10.0.0.1")
        assert logger.verify_chain()

    def test_chain_invalid_after_tampering(self, tmp_path):
        path   = tmp_path / "audit.jsonl"
        logger = SecurityAuditLogger(path)
        logger.log_auth_success("alice", "/predict", "10.0.0.1")
        logger.log_auth_success("bob",   "/predict", "10.0.0.2")
        # Tamper: rewrite first line with altered principal
        lines  = path.read_text().splitlines()
        first  = json.loads(lines[0])
        first["principal"] = "hacked"
        lines[0] = json.dumps(first)
        path.write_text("\n".join(lines) + "\n")
        assert not logger.verify_chain()

    def test_chain_continues_across_instances(self, tmp_path):
        path    = tmp_path / "audit.jsonl"
        logger1 = SecurityAuditLogger(path)
        logger1.log_auth_success("alice", "/predict", "10.0.0.1")
        logger2 = SecurityAuditLogger(path)   # new instance, same file
        logger2.log_auth_success("bob",   "/predict", "10.0.0.2")
        assert logger2.verify_chain()
