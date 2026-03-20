"""
tests/test_governance.py  —  Data governance pipeline tests
AI Fortress · Chapter 2 · Code Sample 2.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import pytest
from models import LegalBasis, DSRType, DSRStatus, TransferMechanism
from lawful_basis import LawfulBasisRegistry
from dsr_workflow import DSRWorkflow
from ropa import RoPAGenerator
from retention import RetentionEngine
from transfer_controls import TransferControlRegistry


@pytest.fixture
def registry():
    return LawfulBasisRegistry()   # in-memory SQLite

@pytest.fixture
def workflow():
    return DSRWorkflow()

@pytest.fixture
def retention():
    return RetentionEngine()


class TestLawfulBasis:
    def test_register_and_retrieve(self, registry):
        d = registry.register(
            dataset_id="ds-001", legal_basis=LegalBasis.CONSENT,
            purpose="Fraud detection training",
            data_categories=["email","transaction_history"],
            retention_days=730,
        )
        fetched = registry.get_dataset("ds-001")
        assert fetched is not None
        assert fetched.legal_basis == LegalBasis.CONSENT
        assert "email" in fetched.data_categories

    def test_consent_grant_and_withdraw(self, registry):
        registry.register("ds-002", LegalBasis.CONSENT, "Test", ["name"], 365)
        c = registry.record_consent("user-1", "ds-002", "Test")
        assert c.is_active

        active = registry.active_consents_for_subject("user-1")
        assert len(active) == 1

        registry.withdraw_consent("user-1", "ds-002")
        active_after = registry.active_consents_for_subject("user-1")
        assert len(active_after) == 0

    def test_consent_coverage_report(self, registry):
        registry.register("ds-003", LegalBasis.CONSENT, "Test", ["name"], 365)
        registry.record_consent("u1", "ds-003", "Test")
        registry.record_consent("u2", "ds-003", "Test")
        registry.withdraw_consent("u2", "ds-003")
        report = registry.consent_coverage_report("ds-003")
        assert report["total"] == 2
        assert report["active"] == 1
        assert report["withdrawn"] == 1


class TestDSRWorkflow:
    def test_submit_erasure(self, workflow):
        req = workflow.submit("user-abc", DSRType.ERASURE, "GDPR")
        assert req.status == DSRStatus.SUBMITTED
        assert "user-abc" in req.subject_id
        assert req.sla_deadline > req.submitted_at

    def test_state_transitions(self, workflow):
        req = workflow.submit("user-xyz", DSRType.ACCESS, "CCPA")
        req = workflow.start_processing(req.request_id)
        assert req.status == DSRStatus.IN_PROGRESS
        req = workflow.complete(req.request_id)
        assert req.status == DSRStatus.COMPLETED
        assert req.completed_at != ""

    def test_reject_with_reason(self, workflow):
        req = workflow.submit("user-q", DSRType.ERASURE, "GDPR")
        req = workflow.reject(req.request_id, "Legal hold in place")
        assert req.status == DSRStatus.REJECTED
        assert "Legal hold" in req.rejection_reason

    def test_sla_report(self, workflow):
        workflow.submit("u1", DSRType.ERASURE, "GDPR")
        workflow.submit("u2", DSRType.ACCESS, "GDPR")
        report = workflow.sla_report()
        assert report["by_status"]["submitted"] == 2

    def test_for_subject(self, workflow):
        workflow.submit("u-specific", DSRType.ERASURE, "GDPR")
        workflow.submit("u-specific", DSRType.ACCESS,  "GDPR")
        reqs = workflow.for_subject("u-specific")
        assert len(reqs) == 2


class TestRetention:
    def test_declare_and_retrieve_policy(self, retention):
        p = retention.declare_policy("ds-r1", "transaction_history", 730)
        policies = retention.policies_for_dataset("ds-r1")
        assert len(policies) == 1
        assert policies[0].retention_days == 730

    def test_deletion_certificate(self, retention):
        cert = retention.issue_deletion_certificate(
            "ds-r1", "email", record_count=500,
            record_ids=["r1","r2","r3"], issued_by="DPO"
        )
        assert cert["record_count"] == 500
        assert len(cert["sha256_manifest"]) == 64
        certs = retention.certificates_for_dataset("ds-r1")
        assert len(certs) == 1


class TestRoPA:
    def test_export(self, tmp_path):
        reg = LawfulBasisRegistry()
        reg.register("ds-ropa", LegalBasis.LEGITIMATE_INTERESTS,
                     "Model training", ["name","ip"], 365,
                     controller="AcmeCorp", processor="CloudML")
        ropa = RoPAGenerator(reg)
        ropa.export_json(tmp_path / "ropa.json")
        import json
        data = json.loads((tmp_path / "ropa.json").read_text())
        assert len(data["records"]) == 1
        assert data["records"][0]["dataset_id"] == "ds-ropa"
