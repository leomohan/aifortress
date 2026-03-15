"""
tests/test_api_hardening.py  —  API hardening tests
AI Fortress · Chapter 5 · Code Sample 5.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import time
import numpy as np
import pytest
from rate_limiter import SlidingWindowRateLimiter, TokenBucketRateLimiter, RateLimitExceeded
from input_validator import InputValidator, InputSpec, InputValidationError
from output_sanitiser import OutputSanitiser
from auth_middleware import AuthMiddleware, AuthenticationError, ScopeError
from abuse_detector import AbuseDetector


class TestSlidingWindowRateLimiter:
    def test_allows_under_limit(self):
        rl = SlidingWindowRateLimiter(requests_per_minute=5)
        for _ in range(5):
            rl.check("key-a")   # should not raise

    def test_blocks_over_limit(self):
        rl = SlidingWindowRateLimiter(requests_per_minute=3)
        for _ in range(3):
            rl.check("key-b")
        with pytest.raises(RateLimitExceeded) as exc_info:
            rl.check("key-b")
        assert exc_info.value.retry_after > 0

    def test_per_key_isolation(self):
        rl = SlidingWindowRateLimiter(requests_per_minute=2)
        rl.check("key-x")
        rl.check("key-x")
        rl.check("key-y")   # different key — should not raise

    def test_reset_clears_window(self):
        rl = SlidingWindowRateLimiter(requests_per_minute=1)
        rl.check("key-c")
        rl.reset("key-c")
        rl.check("key-c")   # should succeed after reset


class TestTokenBucketRateLimiter:
    def test_allows_burst_up_to_capacity(self):
        rl = TokenBucketRateLimiter(capacity=5.0, refill_rate=1.0)
        for _ in range(5):
            rl.check("key-tb")

    def test_blocks_when_empty(self):
        rl = TokenBucketRateLimiter(capacity=2.0, refill_rate=0.1)
        rl.check("key-empty")
        rl.check("key-empty")
        with pytest.raises(RateLimitExceeded):
            rl.check("key-empty")

    def test_refills_over_time(self):
        rl = TokenBucketRateLimiter(capacity=1.0, refill_rate=100.0)
        rl.check("key-refill")   # drain
        # After a tiny sleep, should refill
        time.sleep(0.02)
        rl.check("key-refill")


class TestInputValidator:
    def test_valid_array_passes(self):
        spec = InputSpec(max_shape=[1, 3, 224, 224], allowed_dtypes=["float32"])
        iv   = InputValidator()
        arr  = np.zeros((1, 3, 224, 224), dtype=np.float32)
        iv.validate({"input": arr}, spec)

    def test_shape_violation_raises(self):
        spec = InputSpec(max_shape=[1, 3, 64, 64])
        iv   = InputValidator()
        arr  = np.zeros((1, 3, 512, 512))   # too large
        with pytest.raises(InputValidationError, match="Dimension"):
            iv.validate({"input": arr}, spec)

    def test_nan_rejected(self):
        spec = InputSpec(reject_nan=True)
        iv   = InputValidator()
        arr  = np.array([1.0, float("nan"), 3.0])
        with pytest.raises(InputValidationError, match="NaN"):
            iv.validate({"input": arr}, spec)

    def test_disallowed_dtype_raises(self):
        spec = InputSpec(allowed_dtypes=["float32"])
        iv   = InputValidator()
        arr  = np.zeros((4, 4), dtype=np.float64)
        with pytest.raises(InputValidationError, match="dtype"):
            iv.validate({"input": arr}, spec)

    def test_extra_field_blocked(self):
        spec = InputSpec(allowed_fields={"input"})
        iv   = InputValidator()
        with pytest.raises(InputValidationError, match="Unexpected"):
            iv.validate({"input": [1.0], "exploit": "evil"}, spec)

    def test_required_field_missing(self):
        spec = InputSpec(required_fields={"input"})
        iv   = InputValidator()
        with pytest.raises(InputValidationError, match="Required"):
            iv.validate({}, spec)

    def test_max_tokens_text(self):
        spec = InputSpec(max_tokens=5)
        iv   = InputValidator()
        with pytest.raises(InputValidationError, match="token"):
            iv.validate({"text": "one two three four five six seven"}, spec)


class TestOutputSanitiser:
    def test_high_confidence_suppressed(self):
        san   = OutputSanitiser(suppress_confidence_above=0.9, round_decimals=4)
        probs = np.array([0.98, 0.01, 0.01])
        out   = san.sanitise_classification(probs, ["cat", "dog", "bird"])
        assert out.suppressed
        assert out.data["cat"] <= 0.9 + 1e-6

    def test_top_k_truncation(self):
        san   = OutputSanitiser(top_k=2)
        probs = np.array([0.5, 0.3, 0.1, 0.1])
        out   = san.sanitise_classification(probs)
        assert len(out.data) == 2

    def test_pii_redacted_from_text(self):
        san = OutputSanitiser(redact_pii=True)
        out = san.sanitise_text("Please email me at test@example.com with your SSN 123-45-6789")
        assert "test@example.com" not in out.data
        assert out.pii_redacted

    def test_text_truncation(self):
        san = OutputSanitiser(max_text_chars=20)
        out = san.sanitise_text("A" * 100)
        assert len(out.data) <= 40  # 20 + "[TRUNCATED]"
        assert out.truncated


class TestAuthMiddleware:
    def test_issue_and_authenticate(self):
        am  = AuthMiddleware(signing_secret=b"test-secret-32bytes-xxxxxxxxxx")
        key = am.issue_key(scopes={"inference:read"}, tier="pro")
        api_key = am.authenticate(key, required_scopes={"inference:read"})
        assert api_key.tier == "pro"

    def test_invalid_key_raises(self):
        am = AuthMiddleware(signing_secret=b"test-secret-32bytes-xxxxxxxxxx")
        with pytest.raises(AuthenticationError, match="Invalid"):
            am.authenticate("aif_invalidkeyhere")

    def test_scope_violation_raises(self):
        am  = AuthMiddleware(signing_secret=b"test-secret-32bytes-xxxxxxxxxx")
        key = am.issue_key(scopes={"inference:read"})
        with pytest.raises(ScopeError, match="lacks required scopes"):
            am.authenticate(key, required_scopes={"batch:write"})

    def test_key_rotation(self):
        am      = AuthMiddleware(signing_secret=b"test-secret-32bytes-xxxxxxxxxx", grace_seconds=3600)
        old_key = am.issue_key(scopes={"inference:read"})
        old_kid = list(am._keys.keys())[0]
        new_key = am.rotate_key(old_kid)
        # New key works
        am.authenticate(new_key, required_scopes={"inference:read"})
        # Old key still works during grace period
        am.authenticate(old_key)

    def test_audit_log_populated(self):
        am  = AuthMiddleware(signing_secret=b"test-secret-32bytes-xxxxxxxxxx")
        key = am.issue_key(scopes={"inference:read"})
        am.authenticate(key)
        log = am.audit_log()
        assert any(e["event_type"] == "auth_success" for e in log)


class TestAbuseDetector:
    def test_membership_inference_detected(self):
        det = AbuseDetector(mi_repeat_threshold=3, window_seconds=60)
        payload = b"identical_input_data"
        for _ in range(3):
            alert = det.observe("key-mi", payload, 1024)
        assert alert is not None
        assert alert.alert_type == "membership_inference"

    def test_model_extraction_detected(self):
        det = AbuseDetector(
            extraction_query_threshold=10,
            extraction_diversity_ratio=0.8,
            window_seconds=60,
        )
        alerts = []
        for i in range(10):
            a = det.observe("key-ext", f"unique_input_{i}".encode(), 512)
            if a:
                alerts.append(a)
        extraction_alerts = [a for a in alerts if a.alert_type == "extraction"]
        assert len(extraction_alerts) > 0

    def test_no_alert_for_normal_usage(self):
        det = AbuseDetector(
            extraction_query_threshold=1000,
            mi_repeat_threshold=50,
            window_seconds=300,
        )
        for i in range(10):
            alert = det.observe("key-normal", f"query_{i}".encode(), 1024)
        assert alert is None

    def test_summary(self):
        det = AbuseDetector(mi_repeat_threshold=2, window_seconds=60)
        payload = b"same_input"
        for _ in range(2):
            det.observe("key-s", payload, 100)
        s = det.summary()
        assert "total_alerts" in s
