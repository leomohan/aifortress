"""
tests/test_service_mesh.py
AI Fortress · Chapter 9 · Code Sample 9.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import datetime
import json
import time
import pytest

from workload_identity_verifier import WorkloadIdentityVerifier
from authz_policy_engine import AuthzPolicyEngine, AuthzRule
from lateral_movement_detector import LateralMovementDetector
from mtls_cert_validator import MTLSCertValidator


# ── Fixtures ──────────────────────────────────────────────────────────────────

TRUST_DOMAIN = "ml-platform.example.com"
WORKLOAD     = "ns/inference/sa/model-server"
SPIFFE_ID    = f"spiffe://{TRUST_DOMAIN}/{WORKLOAD}"


@pytest.fixture(scope="module")
def svid_bundle():
    """Generate a test SVID and CA cert, reused across tests."""
    cert_pem, key_pem, ca_pem, ca_key, ca_cert = \
        WorkloadIdentityVerifier.generate_test_svid(TRUST_DOMAIN, WORKLOAD)
    return cert_pem, key_pem, ca_pem, ca_key, ca_cert


# ── WorkloadIdentityVerifier ──────────────────────────────────────────────────

class TestWorkloadIdentityVerifier:

    def test_valid_svid_verified(self, svid_bundle):
        cert_pem, _, ca_pem, _, _ = svid_bundle
        verifier = WorkloadIdentityVerifier([ca_pem])
        result   = verifier.verify_pem(cert_pem)
        assert result.verified
        assert result.identity.spiffe_id == SPIFFE_ID
        assert result.identity.trust_domain == TRUST_DOMAIN

    def test_wrong_ca_rejected(self, svid_bundle):
        cert_pem, _, _, _, _ = svid_bundle
        # Use a different CA cert
        _, _, other_ca_pem, _, _ = WorkloadIdentityVerifier.generate_test_svid(
            "other.example.com", "workload")
        verifier = WorkloadIdentityVerifier([other_ca_pem])
        result   = verifier.verify_pem(cert_pem)
        assert not result.verified
        assert "signed" in result.reason.lower()

    def test_wrong_trust_domain_rejected(self, svid_bundle):
        cert_pem, _, ca_pem, _, _ = svid_bundle
        verifier = WorkloadIdentityVerifier([ca_pem],
                                            allowed_trust_domains={"other.example.com"})
        result   = verifier.verify_pem(cert_pem)
        assert not result.verified
        assert "trust domain" in result.reason.lower()

    def test_allowed_trust_domain_passes(self, svid_bundle):
        cert_pem, _, ca_pem, _, _ = svid_bundle
        verifier = WorkloadIdentityVerifier([ca_pem],
                                            allowed_trust_domains={TRUST_DOMAIN})
        result   = verifier.verify_pem(cert_pem)
        assert result.verified

    def test_not_in_allowed_spiffe_ids_rejected(self, svid_bundle):
        cert_pem, _, ca_pem, _, _ = svid_bundle
        verifier = WorkloadIdentityVerifier([ca_pem],
                                            allowed_spiffe_ids={"spiffe://other/workload"})
        result   = verifier.verify_pem(cert_pem)
        assert not result.verified

    def test_expired_cert_rejected(self, svid_bundle):
        _, _, ca_pem, ca_key, ca_cert = svid_bundle
        cert_pem, _, _, _, _ = WorkloadIdentityVerifier.generate_test_svid(
            TRUST_DOMAIN, WORKLOAD, ca_key=ca_key, ca_cert=ca_cert, ttl_days=-1)
        verifier = WorkloadIdentityVerifier([ca_pem])
        result   = verifier.verify_pem(cert_pem)
        assert not result.verified
        assert "expired" in result.reason.lower()

    def test_workload_path_extracted(self, svid_bundle):
        cert_pem, _, ca_pem, _, _ = svid_bundle
        verifier = WorkloadIdentityVerifier([ca_pem])
        result   = verifier.verify_pem(cert_pem)
        assert result.identity.workload == WORKLOAD

    def test_invalid_pem_rejected(self):
        verifier = WorkloadIdentityVerifier([])
        result   = verifier.verify_pem(b"not a certificate")
        assert not result.verified


# ── AuthzPolicyEngine ─────────────────────────────────────────────────────────

SAMPLE_POLICY = [
    {
        "id":          "allow-inference-to-features",
        "source":      SPIFFE_ID,
        "destination": "feature-store",
        "methods":     ["GET"],
        "paths":       ["/v1/features/*"],
        "effect":      "allow",
    },
    {
        "id":          "allow-training-to-data",
        "source":      "spiffe://ml-platform.example.com/ns/training/*",
        "destination": "data-store",
        "methods":     ["GET", "POST"],
        "paths":       ["*"],
        "effect":      "allow",
    },
    {
        "id":     "deny-all",
        "source": "*", "destination": "*",
        "methods": ["*"], "paths": ["*"],
        "effect": "deny",
    },
]


class TestAuthzPolicyEngine:

    def _engine(self, policy=None):
        return AuthzPolicyEngine.from_dict(policy or SAMPLE_POLICY)

    def test_allowed_call_passes(self):
        dec = self._engine().evaluate(SPIFFE_ID, "feature-store", "GET", "/v1/features/user123")
        assert dec.allowed
        assert dec.rule_id == "allow-inference-to-features"

    def test_wrong_method_denied(self):
        dec = self._engine().evaluate(SPIFFE_ID, "feature-store", "POST", "/v1/features/user123")
        assert not dec.allowed

    def test_wrong_path_denied(self):
        dec = self._engine().evaluate(SPIFFE_ID, "feature-store", "GET", "/admin/reset")
        assert not dec.allowed

    def test_wrong_source_denied(self):
        dec = self._engine().evaluate("spiffe://evil/workload", "feature-store",
                                      "GET", "/v1/features/x")
        assert not dec.allowed

    def test_default_deny_no_rule(self):
        engine = AuthzPolicyEngine()   # no rules
        dec    = engine.evaluate(SPIFFE_ID, "feature-store", "GET", "/v1/features/x")
        assert not dec.allowed
        assert dec.rule_id == "default-deny"

    def test_wildcard_source_matches(self):
        dec = self._engine().evaluate(
            "spiffe://ml-platform.example.com/ns/training/sa/job-runner",
            "data-store", "POST", "/data/upload")
        assert dec.allowed

    def test_wildcard_path_matches(self):
        dec = self._engine().evaluate(
            "spiffe://ml-platform.example.com/ns/training/sa/anything",
            "data-store", "GET", "/any/path/here")
        assert dec.allowed

    def test_audit_log_written(self, tmp_path):
        log    = tmp_path / "authz.jsonl"
        engine = AuthzPolicyEngine.from_dict(SAMPLE_POLICY, audit_path=log)
        engine.evaluate(SPIFFE_ID, "feature-store", "GET", "/v1/features/x")
        lines  = log.read_text().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["allowed"] is True

    def test_add_rule_at_front(self):
        engine = AuthzPolicyEngine()
        rule   = AuthzRule("custom", SPIFFE_ID, "special-svc", ["GET"], ["/*"], "allow")
        engine.add_rule(rule, position=0)
        dec    = engine.evaluate(SPIFFE_ID, "special-svc", "GET", "/anything")
        assert dec.allowed


# ── LateralMovementDetector ───────────────────────────────────────────────────

class TestLateralMovementDetector:

    SOURCE = "spiffe://platform/ns/inference/sa/model-server"

    def test_normal_traffic_no_alerts(self):
        det = LateralMovementDetector(
            approved_peers={"spiffe://platform/ns/inference/sa/model-server": {"feature-store"}},
        )
        alerts = det.observe(self.SOURCE, "feature-store")
        assert len(alerts) == 0

    def test_unexpected_destination_alert(self):
        det = LateralMovementDetector(
            approved_peers={self.SOURCE: {"feature-store"}},
        )
        alerts = det.observe(self.SOURCE, "secret-manager")
        signals = [a.signal for a in alerts]
        assert "unexpected_dest" in signals

    def test_high_value_target_alert(self):
        det = LateralMovementDetector(
            high_value_services={"model-registry"},
        )
        alerts = det.observe(self.SOURCE, "model-registry")
        signals = [a.signal for a in alerts]
        assert "high_value_target" in signals

    def test_high_value_only_once(self):
        det = LateralMovementDetector(high_value_services={"model-registry"})
        alerts1 = det.observe(self.SOURCE, "model-registry")
        alerts2 = det.observe(self.SOURCE, "model-registry")
        # Second call: no new high_value alert
        assert any(a.signal == "high_value_target" for a in alerts1)
        assert not any(a.signal == "high_value_target" for a in alerts2)

    def test_fan_out_explosion_alert(self):
        det = LateralMovementDetector(fan_out_threshold=3, window_seconds=60)
        now = time.time()
        alerts_all = []
        for i in range(5):
            alerts_all.extend(det.observe(self.SOURCE, f"svc-{i}", ts=now))
        assert any(a.signal == "fan_out" for a in alerts_all)

    def test_high_freq_probe_alert(self):
        det = LateralMovementDetector(probe_threshold=10, window_seconds=60)
        now = time.time()
        alerts_all = []
        for _ in range(12):
            alerts_all.extend(det.observe(self.SOURCE, "target-svc", ts=now))
        assert any(a.signal == "high_freq_probe" for a in alerts_all)

    def test_alert_written_to_file(self, tmp_path):
        log = tmp_path / "alerts.jsonl"
        det = LateralMovementDetector(
            high_value_services={"model-registry"},
            alert_path=log,
        )
        det.observe(self.SOURCE, "model-registry")
        lines = log.read_text().splitlines()
        assert len(lines) >= 1
        assert json.loads(lines[0])["signal"] == "high_value_target"

    def test_call_stats(self):
        det = LateralMovementDetector()
        for svc in ["svc-a", "svc-b", "svc-a"]:
            det.observe(self.SOURCE, svc)
        stats = det.get_call_stats(self.SOURCE)
        assert stats["calls_in_window"] == 3
        assert stats["unique_destinations"] == 2


# ── MTLSCertValidator ─────────────────────────────────────────────────────────

class TestMTLSCertValidator:

    @pytest.fixture(scope="class")
    def certs(self):
        cert_pem, key_pem, ca_pem, ca_key, ca_cert = \
            WorkloadIdentityVerifier.generate_test_svid(TRUST_DOMAIN, WORKLOAD)
        return cert_pem, key_pem, ca_pem, ca_key, ca_cert

    def test_valid_cert_passes(self, certs):
        cert_pem, _, ca_pem, _, _ = certs
        v      = MTLSCertValidator(trusted_ca_pems=[ca_pem])
        result = v.validate_pem(cert_pem)
        assert result.valid

    def test_san_uri_contains_spiffe(self, certs):
        cert_pem, _, ca_pem, _, _ = certs
        v      = MTLSCertValidator(trusted_ca_pems=[ca_pem])
        result = v.validate_pem(cert_pem)
        assert any("spiffe://" in uri for uri in result.san_uri)

    def test_expected_san_match(self, certs):
        cert_pem, _, ca_pem, _, _ = certs
        v = MTLSCertValidator(
            trusted_ca_pems=[ca_pem],
            expected_sans=[SPIFFE_ID],
        )
        result = v.validate_pem(cert_pem)
        assert result.valid
        assert not any(i.code == "SAN_MISMATCH" for i in result.issues)

    def test_expected_san_mismatch_fails(self, certs):
        cert_pem, _, ca_pem, _, _ = certs
        v = MTLSCertValidator(
            trusted_ca_pems=[ca_pem],
            expected_sans=["spiffe://other/workload"],
        )
        result = v.validate_pem(cert_pem)
        assert not result.valid
        assert any(i.code == "SAN_MISMATCH" for i in result.issues)

    def test_expired_cert_critical(self, certs):
        _, _, _, ca_key, ca_cert = certs
        _, _, ca_pem, _, _ = certs
        exp_pem, _, _, _, _ = WorkloadIdentityVerifier.generate_test_svid(
            TRUST_DOMAIN, WORKLOAD, ca_key=ca_key, ca_cert=ca_cert, ttl_days=-1)
        v      = MTLSCertValidator(trusted_ca_pems=[ca_pem])
        result = v.validate_pem(exp_pem)
        assert not result.valid
        assert result.expiry_level == "CRITICAL"

    def test_wrong_ca_chain_fails(self, certs):
        cert_pem, _, _, _, _ = certs
        _, _, other_ca_pem, _, _ = WorkloadIdentityVerifier.generate_test_svid(
            "other.example.com", "workload")
        v      = MTLSCertValidator(trusted_ca_pems=[other_ca_pem])
        result = v.validate_pem(cert_pem)
        assert not result.valid
        assert any(i.code == "CHAIN_INVALID" for i in result.issues)

    def test_key_type_recorded(self, certs):
        cert_pem, _, ca_pem, _, _ = certs
        v      = MTLSCertValidator(trusted_ca_pems=[ca_pem])
        result = v.validate_pem(cert_pem)
        assert result.key_type.startswith("EC-")

    def test_parse_error_handled(self):
        v      = MTLSCertValidator()
        result = v.validate_pem(b"not a certificate")
        assert not result.valid
        assert any(i.code == "PARSE_ERROR" for i in result.issues)
