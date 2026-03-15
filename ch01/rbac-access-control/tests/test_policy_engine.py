"""
tests/test_policy_engine.py  —  RBAC + ABAC decision matrix tests
AI Fortress · Chapter 1 · Code Sample 1.B
Run: pytest tests/ -v
"""
import pytest
from roles import BUILTIN_ROLES, Classification
from policy_engine import PolicyEngine

engine = PolicyEngine(BUILTIN_ROLES)


class TestPermits:
    def test_ml_engineer_read_confidential_dataset(self):
        d = engine.evaluate("alice", "ml-engineer", "read",
                             "s3://bucket/datasets/processed/train.parquet", "CONFIDENTIAL")
        assert d.permitted

    def test_data_engineer_write_processed(self):
        d = engine.evaluate("bob", "data-engineer", "write",
                             "s3://bucket/processed/train.parquet", "INTERNAL")
        assert d.permitted

    def test_auditor_read_audit_logs_restricted(self):
        d = engine.evaluate("carol", "auditor", "read",
                             "s3://bucket/audit-logs/2024-01.jsonl", "RESTRICTED")
        assert d.permitted

    def test_admin_delete_anything(self):
        d = engine.evaluate("sre", "admin", "delete",
                             "s3://bucket/models/v1/weights.bin", "RESTRICTED")
        assert d.permitted


class TestDenies:
    def test_unknown_role(self):
        d = engine.evaluate("x", "unknown-role", "read", "s3://bucket/data/f.parquet")
        assert not d.permitted
        assert "Unknown role" in d.reason

    def test_researcher_above_ceiling(self):
        d = engine.evaluate("dave", "ml-researcher", "read",
                             "s3://bucket/datasets/non-pii/f.parquet", "CONFIDENTIAL")
        assert not d.permitted
        assert "ceiling" in d.reason

    def test_researcher_write_denied(self):
        d = engine.evaluate("dave", "ml-researcher", "write",
                             "s3://bucket/datasets/non-pii/f.parquet", "INTERNAL")
        assert not d.permitted
        assert "action" in d.reason

    def test_data_engineer_access_models(self):
        d = engine.evaluate("eve", "data-engineer", "read",
                             "s3://bucket/models/v2/weights.bin", "CONFIDENTIAL")
        assert not d.permitted
        assert "prefix" in d.reason

    def test_unknown_classification(self):
        d = engine.evaluate("f", "ml-engineer", "read",
                             "s3://bucket/datasets/f.parquet", "TOP_SECRET")
        assert not d.permitted
        assert "classification" in d.reason.lower()


class TestAuditLogger:
    def test_records_written(self, tmp_path):
        from policy_engine import AuditLogger
        log = AuditLogger(tmp_path / "access.jsonl")
        d1  = engine.evaluate("a", "ml-engineer", "read", "s3://b/datasets/f.parquet", "INTERNAL")
        d2  = engine.evaluate("a", "ml-researcher", "write", "s3://b/datasets/f.parquet", "INTERNAL")
        log.record(d1); log.record(d2)
        entries = log.tail(10)
        assert len(entries) == 2
        assert entries[0]["permitted"] is True
        assert entries[1]["permitted"] is False
