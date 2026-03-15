"""
tests/test_storage_hardening.py
AI Fortress · Chapter 7 · Code Sample 7.B
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from bucket_policy_auditor import BucketPolicyAuditor
from encryption_verifier import EncryptionVerifier
from public_access_scanner import PublicAccessScanner
from lifecycle_enforcer import LifecycleEnforcer


# ── BucketPolicyAuditor ───────────────────────────────────────────────────────

class TestBucketPolicyAuditor:

    def test_no_policy_flagged(self):
        auditor = BucketPolicyAuditor()
        result  = auditor.audit("ml-models", None)
        assert any(f.check_id == "BP-000" for f in result.findings)

    def test_public_principal_detected(self):
        auditor = BucketPolicyAuditor()
        policy  = {"Statement": [{"Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
                                   "Action": "s3:GetObject", "Resource": "arn:aws:s3:::ml-models/*"}]}
        result  = auditor.audit("ml-models", policy)
        assert any(f.check_id == "BP-001" and f.severity == "CRITICAL" for f in result.findings)

    def test_delete_without_mfa_detected(self):
        auditor = BucketPolicyAuditor()
        policy  = {"Statement": [{"Sid": "AllowDelete", "Effect": "Allow",
                                   "Principal": {"AWS": "arn:aws:iam::123456789012:role/MLRole"},
                                   "Action": ["s3:DeleteObject"], "Resource": "*"}]}
        result  = auditor.audit("ml-models", policy)
        assert any(f.check_id == "BP-003" for f in result.findings)

    def test_missing_secure_transport_flagged(self):
        auditor = BucketPolicyAuditor()
        # Policy with no SecureTransport Deny
        policy  = {"Statement": [{"Sid": "ReadOnly", "Effect": "Allow",
                                   "Principal": {"AWS": "arn:aws:iam::123:role/Reader"},
                                   "Action": "s3:GetObject", "Resource": "*"}]}
        result  = auditor.audit("ml-models", policy)
        assert any(f.check_id == "BP-004" for f in result.findings)

    def test_compliant_policy_passes(self):
        auditor = BucketPolicyAuditor()
        policy  = {
            "Statement": [
                {
                    "Sid": "DenyHTTP", "Effect": "Deny", "Principal": "*",
                    "Action": "s3:*", "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
                {
                    "Sid": "DenyUnencrypted", "Effect": "Deny", "Principal": "*",
                    "Action": "s3:PutObject", "Resource": "*",
                    "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}},
                },
            ]
        }
        result = auditor.audit("ml-models", policy)
        assert result.critical == 0
        assert result.high     == 0

    def test_score_decreases_with_findings(self):
        auditor = BucketPolicyAuditor()
        result  = auditor.audit("ml-models", None)
        assert result.score < 100

    def test_passed_flag(self):
        auditor = BucketPolicyAuditor()
        policy  = {"Statement": [
            {"Sid": "DenyHTTP", "Effect": "Deny", "Principal": "*",
             "Action": "s3:*", "Resource": "*",
             "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
            {"Sid": "DenyUnencrypted", "Effect": "Deny", "Principal": "*",
             "Action": "s3:PutObject", "Resource": "*",
             "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}},
        ]}
        result = auditor.audit("ml-models", policy)
        assert result.passed


# ── EncryptionVerifier ────────────────────────────────────────────────────────

class TestEncryptionVerifier:

    def test_unencrypted_s3_detected(self):
        ev     = EncryptionVerifier()
        config = {"s3_buckets": [{"name": "ml-data", "sse_algorithm": ""}]}
        report = ev.verify(config)
        assert any(f.check_id == "EV-001" and f.severity == "CRITICAL" for f in report.findings)

    def test_sse_s3_without_cmk_detected(self):
        ev     = EncryptionVerifier(require_cmk=True)
        config = {"s3_buckets": [{"name": "ml-data", "sse_algorithm": "AES256"}]}
        report = ev.verify(config)
        assert any(f.check_id == "EV-002" and f.severity == "HIGH" for f in report.findings)

    def test_kms_without_rotation_detected(self):
        ev     = EncryptionVerifier(require_key_rotation=True)
        config = {"s3_buckets": [{
            "name": "ml-data",
            "sse_algorithm": "aws:kms",
            "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc",
            "kms_key_rotation_enabled": False,
        }]}
        report = ev.verify(config)
        assert any(f.check_id == "EV-004" for f in report.findings)

    def test_compliant_s3_passes(self):
        ev     = EncryptionVerifier()
        config = {"s3_buckets": [{
            "name": "ml-data",
            "sse_algorithm": "aws:kms",
            "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc",
            "kms_key_rotation_enabled": True,
        }]}
        report = ev.verify(config)
        assert report.overall_pass

    def test_unencrypted_ebs_detected(self):
        ev     = EncryptionVerifier()
        config = {"ebs_volumes": [{"volume_id": "vol-abc", "encrypted": False}]}
        report = ev.verify(config)
        assert any(f.check_id == "EV-005" and f.severity == "CRITICAL" for f in report.findings)

    def test_unencrypted_efs_detected(self):
        ev     = EncryptionVerifier()
        config = {"efs_filesystems": [{"filesystem_id": "fs-abc", "encrypted": False}]}
        report = ev.verify(config)
        assert any(f.check_id == "EV-007" and f.severity == "CRITICAL" for f in report.findings)

    def test_summary_string(self):
        ev     = EncryptionVerifier()
        config = {"s3_buckets": [{"name": "ok", "sse_algorithm": "aws:kms",
                                   "kms_key_id": "arn:...", "kms_key_rotation_enabled": True}]}
        report = ev.verify(config)
        assert "Encryption check" in report.summary()

    def test_save_json(self, tmp_path):
        ev     = EncryptionVerifier()
        config = {"s3_buckets": [{"name": "ml-data", "sse_algorithm": ""}]}
        report = ev.verify(config)
        path   = tmp_path / "enc_report.json"
        report.save_json(path)
        data   = json.loads(path.read_text())
        assert "findings" in data


# ── PublicAccessScanner ───────────────────────────────────────────────────────

class TestPublicAccessScanner:

    def test_bpa_flag_missing_detected(self):
        scanner = PublicAccessScanner()
        config  = {"block_public_access": {"block_public_acls": False,
                                            "ignore_public_acls": True,
                                            "block_public_policy": True,
                                            "restrict_public_buckets": True}}
        report  = scanner.scan("ml-models", config)
        assert any(f.check_id == "PA-001" for f in report.findings)

    def test_public_acl_detected(self):
        scanner = PublicAccessScanner()
        config  = {"acl": "public-read",
                   "block_public_access": {"block_public_acls": True, "ignore_public_acls": True,
                                           "block_public_policy": True, "restrict_public_buckets": True}}
        report  = scanner.scan("ml-models", config)
        assert any(f.check_id == "PA-002" and f.severity == "CRITICAL" for f in report.findings)
        assert report.is_public

    def test_presigned_url_too_long(self):
        scanner = PublicAccessScanner(max_presigned_url_seconds=3600)
        config  = {"block_public_access": {"block_public_acls": True, "ignore_public_acls": True,
                                           "block_public_policy": True, "restrict_public_buckets": True},
                   "acl": "private",
                   "presigned_url_max_seconds": 86400}  # 24h — too long
        report  = scanner.scan("ml-models", config)
        assert any(f.check_id == "PA-004" for f in report.findings)

    def test_compliant_bucket_not_public(self):
        scanner = PublicAccessScanner()
        config  = {
            "block_public_access": {"block_public_acls": True, "ignore_public_acls": True,
                                    "block_public_policy": True, "restrict_public_buckets": True},
            "acl": "private",
            "presigned_url_max_seconds": 900,
        }
        report = scanner.scan("ml-models", config)
        assert not report.is_public

    def test_policy_public_principal(self):
        scanner = PublicAccessScanner()
        config  = {
            "block_public_access": {"block_public_acls": True, "ignore_public_acls": True,
                                    "block_public_policy": True, "restrict_public_buckets": True},
            "acl": "private",
            "policy": {"Statement": [{"Sid": "PubRead", "Effect": "Allow",
                                       "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]},
        }
        report = scanner.scan("ml-models", config)
        assert any(f.check_id == "PA-003" for f in report.findings)


# ── LifecycleEnforcer ─────────────────────────────────────────────────────────

class TestLifecycleEnforcer:

    def test_no_versioning_detected(self):
        le     = LifecycleEnforcer()
        config = {"versioning": {"status": "Suspended"}, "lifecycle_rules": []}
        report = le.check("ml-models", config)
        assert any(f.check_id == "LC-001" for f in report.findings)
        assert not report.versioning_ok

    def test_no_lifecycle_rules_detected(self):
        le     = LifecycleEnforcer()
        config = {"versioning": {"status": "Enabled"}, "lifecycle_rules": []}
        report = le.check("ml-models", config)
        assert any(f.check_id == "LC-002" for f in report.findings)

    def test_missing_noncurrent_expiry_detected(self):
        le = LifecycleEnforcer()
        config = {
            "versioning": {"status": "Enabled"},
            "lifecycle_rules": [
                {"transitions": [{"storage_class": "STANDARD_IA", "days": 30}]}
            ]
        }
        report = le.check("ml-models", config)
        assert any(f.check_id == "LC-003" for f in report.findings)

    def test_compliant_config_passes(self):
        le = LifecycleEnforcer()
        config = {
            "versioning": {"status": "Enabled"},
            "lifecycle_rules": [
                {
                    "transitions": [{"storage_class": "STANDARD_IA", "days": 30}],
                    "noncurrent_version_expiration": {"noncurrent_days": 90},
                }
            ]
        }
        report = le.check("ml-models", config)
        assert report.overall_pass

    def test_generate_policy_structure(self):
        le     = LifecycleEnforcer()
        policy = le.generate_policy("ml-models", prefix="checkpoints/")
        rules  = policy["Rules"]
        assert len(rules) == 1
        rule = rules[0]
        assert "Transitions" in rule
        assert "NoncurrentVersionExpiration" in rule
        assert rule["Status"] == "Enabled"

    def test_summary_string(self):
        le     = LifecycleEnforcer()
        config = {"versioning": {"status": "Enabled"}, "lifecycle_rules": []}
        report = le.check("ml-models", config)
        assert "ml-models" in report.summary()
