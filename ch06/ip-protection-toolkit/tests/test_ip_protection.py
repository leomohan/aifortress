"""
tests/test_ip_protection.py
AI Fortress · Chapter 6 · Code Sample 6.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import socket
import numpy as np
import pytest
from model_fingerprinter import ModelFingerprinter, ModelFingerprint
from ownership_verifier import OwnershipVerifier
from membership_defence import MembershipDefence
from licence_enforcer import LicenceIssuer, LicenceEnforcer, LicenceViolationError


# ── Toy models ────────────────────────────────────────────────────────────────

def softmax(x):
    e = np.exp(x - x.max())
    return e / e.sum()

def make_fixed_model(n_classes=4, seed=0):
    """Deterministic model: argmax of linear transform."""
    rng = np.random.default_rng(seed)
    W   = rng.normal(0, 1, (n_classes, 10))
    def fn(x):
        return softmax(W @ x.flatten()[:10])
    return fn


# ── ModelFingerprinter ────────────────────────────────────────────────────────

class TestModelFingerprinter:
    def test_generate_creates_fingerprint(self):
        fp_gen  = ModelFingerprinter("owner-1", n_queries=20)
        model   = make_fixed_model(seed=0)
        fp      = fp_gen.generate(model, [10], "fraud-v1", secret=b"secret")
        assert len(fp.responses)  == 20
        assert len(fp.queries)    == 20
        assert fp.owner_id        == "owner-1"

    def test_same_model_matches(self):
        fp_gen = ModelFingerprinter("owner-1", n_queries=30, match_threshold=0.70)
        model  = make_fixed_model(seed=42)
        fp     = fp_gen.generate(model, [10], "m", secret=b"sec")
        result = fp_gen.match(fp, model)   # same model → should match
        assert result.agreement_rate == 1.0
        assert result.match

    def test_different_model_no_match(self):
        fp_gen  = ModelFingerprinter("owner-1", n_queries=30, match_threshold=0.70)
        model_a = make_fixed_model(seed=0)
        model_b = make_fixed_model(seed=99)
        fp      = fp_gen.generate(model_a, [10], "m", secret=b"sec")
        result  = fp_gen.match(fp, model_b)
        # Different models should disagree significantly
        assert result.agreement_rate < 0.90   # not a perfect match

    def test_fingerprint_save_load(self, tmp_path):
        fp_gen = ModelFingerprinter("owner-2", n_queries=10)
        model  = make_fixed_model()
        fp     = fp_gen.generate(model, [10], "m", secret=b"s")
        path   = tmp_path / "fp.json"
        fp.save(path)
        loaded = ModelFingerprint.load(path)
        assert loaded.fingerprint_id == fp.fingerprint_id
        assert loaded.responses      == fp.responses


# ── OwnershipVerifier ─────────────────────────────────────────────────────────

class TestOwnershipVerifier:
    def test_confirms_same_model(self):
        fp_gen = ModelFingerprinter("owner-1", n_queries=30, match_threshold=0.70)
        model  = make_fixed_model(seed=7)
        fp     = fp_gen.generate(model, [10], "fraud-v2", secret=b"owner-secret")
        verifier = OwnershipVerifier("owner-1", fp)
        report   = verifier.verify(model, model_name="fraud-v2")
        assert report.fingerprint_match
        assert report.overall_verdict == "OWNER_CONFIRMED"

    def test_rejects_different_model(self):
        fp_gen   = ModelFingerprinter("owner-1", n_queries=30, match_threshold=0.90)
        model_a  = make_fixed_model(seed=1)
        model_b  = make_fixed_model(seed=2)
        fp       = fp_gen.generate(model_a, [10], "m", secret=b"s")
        verifier = OwnershipVerifier("owner-1", fp)
        report   = verifier.verify(model_b)
        assert report.overall_verdict in ("NOT_OWNER", "INCONCLUSIVE")

    def test_report_save(self, tmp_path):
        fp_gen   = ModelFingerprinter("owner-1", n_queries=10)
        model    = make_fixed_model()
        fp       = fp_gen.generate(model, [10], "m", secret=b"s")
        verifier = OwnershipVerifier("owner-1", fp)
        report   = verifier.verify(model)
        path     = tmp_path / "report.json"
        report.save(path)
        data = json.loads(path.read_text())
        assert "overall_verdict" in data


# ── MembershipDefence ─────────────────────────────────────────────────────────

class TestMembershipDefence:
    def test_laplace_noise_changes_probs(self):
        defence = MembershipDefence(epsilon_dp=1.0, mechanism="laplace")
        probs   = np.array([0.7, 0.2, 0.1])
        result  = defence.defend(probs)
        assert not np.allclose(result.original_probs, result.defended_probs)

    def test_gaussian_noise_changes_probs(self):
        defence = MembershipDefence(epsilon_dp=1.0, mechanism="gaussian")
        probs   = np.array([0.6, 0.3, 0.1])
        result  = defence.defend(probs)
        assert not np.allclose(result.original_probs, result.defended_probs)

    def test_defended_probs_sum_to_one(self):
        defence = MembershipDefence(epsilon_dp=2.0, clip_to_simplex=True)
        probs   = np.array([0.5, 0.3, 0.2])
        result  = defence.defend(probs)
        assert abs(result.defended_probs.sum() - 1.0) < 1e-6

    def test_defended_probs_non_negative(self):
        defence = MembershipDefence(epsilon_dp=0.5)   # strong noise
        probs   = np.array([0.5, 0.3, 0.2])
        result  = defence.defend(probs)
        assert result.defended_probs.min() >= 0.0

    def test_top_k_returns_k_classes(self):
        defence = MembershipDefence(epsilon_dp=5.0)
        probs   = np.array([0.4, 0.3, 0.2, 0.1])
        out     = defence.defend_top_k(probs, k=2)
        assert (out > 0).sum() == 2
        assert abs(out.sum() - 1.0) < 1e-6


# ── LicenceEnforcer ───────────────────────────────────────────────────────────

class TestLicenceEnforcer:
    def _issue(self, **kwargs):
        issuer = LicenceIssuer()
        defaults = dict(
            model_name="fraud-detector",
            model_version="1.0",
            licensee_id="acme-corp",
            permitted_scopes=["inference"],
            expires_at="",
            permitted_hostnames=[],
            max_deployments=0,
        )
        defaults.update(kwargs)
        return issuer, issuer.issue(**defaults)

    def test_valid_licence_passes(self):
        _, policy  = self._issue()
        enforcer   = LicenceEnforcer(use_scope="inference")
        enforcer.enforce(policy)   # should not raise

    def test_expired_licence_raises(self):
        _, policy = self._issue(expires_at="2000-01-01T00:00:00+00:00")
        enforcer  = LicenceEnforcer(use_scope="inference")
        with pytest.raises(LicenceViolationError, match="expired"):
            enforcer.enforce(policy)

    def test_wrong_scope_raises(self):
        _, policy = self._issue(permitted_scopes=["inference"])
        enforcer  = LicenceEnforcer(use_scope="fine-tuning")
        with pytest.raises(LicenceViolationError, match="scope"):
            enforcer.enforce(policy)

    def test_wrong_hostname_raises(self):
        _, policy = self._issue(permitted_hostnames=["authorised-host-xyz"])
        enforcer  = LicenceEnforcer(use_scope="inference")
        # Current host is almost certainly not "authorised-host-xyz"
        if socket.gethostname() != "authorised-host-xyz":
            with pytest.raises(LicenceViolationError, match="host"):
                enforcer.enforce(policy)

    def test_tampered_signature_raises(self, tmp_path):
        _, policy = self._issue()
        # Tamper
        d = policy.to_dict()
        d["licensee_id"] = "evil-corp"
        from licence_enforcer import LicencePolicy
        tampered = LicencePolicy(**d)
        enforcer = LicenceEnforcer(use_scope="inference")
        with pytest.raises(LicenceViolationError, match="signature"):
            enforcer.enforce(tampered)

    def test_save_load_roundtrip(self, tmp_path):
        _, policy = self._issue()
        path      = tmp_path / "licence.json"
        policy.save(path)
        from licence_enforcer import LicencePolicy
        loaded   = LicencePolicy.load(path)
        enforcer = LicenceEnforcer(use_scope="inference")
        enforcer.enforce(loaded)   # should still pass
