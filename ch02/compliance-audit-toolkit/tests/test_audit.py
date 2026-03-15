"""
tests/test_audit.py  —  Compliance audit toolkit tests
AI Fortress · Chapter 2 · Code Sample 2.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import pytest
from control_registry import ControlRegistry, ControlStatus
from evidence_collector import EvidenceCollector, AuditEvidence
from gap_analyser import GapAnalyser
from report_generator import ReportGenerator
from dpia_template import generate_ml_dpia


class TestControlRegistry:
    def test_gdpr_controls_present(self):
        reg = ControlRegistry()
        gdpr = reg.for_regulation("GDPR")
        assert len(gdpr) >= 8
        ids = [c.control_id for c in gdpr]
        assert "GDPR-01" in ids
        assert "GDPR-09" in ids   # RoPA

    def test_all_regulations_covered(self):
        reg = ControlRegistry()
        for r in ["GDPR", "CCPA", "HIPAA", "EU_AI_ACT"]:
            assert len(reg.for_regulation(r)) > 0


class TestGapAnalyser:
    def test_all_gaps_when_no_evidence(self):
        evidence = AuditEvidence("ds-001", {})
        report   = GapAnalyser().analyse(evidence, ["GDPR"])
        gaps     = report.by_status(ControlStatus.GAP)
        assert len(gaps) > 0
        assert len(report.by_status(ControlStatus.COMPLIANT)) == 0

    def test_fully_compliant_when_all_evidence(self):
        all_keys = {
            "lawful_basis_registered": True,
            "purpose_documented": True,
            "data_categories_documented": True,
            "retention_policy_declared": True,
            "deletion_certificates_present": True,
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "access_controls_documented": True,
            "dsr_workflow_operational": True,
            "erasure_sla_met": True,
            "ropa_current": True,
            "dpia_completed": True,
            "pseudonymisation_applied": True,
            "transfer_controls_documented": True,
            "audit_logs_present": True,
            "integrity_verification_present": True,
            "privacy_notice_present": True,
            "opt_out_mechanism_documented": True,
            "baa_documented": True,
            "minimisation_review": True,
            "transparency_documentation_present": True,
            "risk_register_present": True,
        }
        evidence = AuditEvidence("ds-full", all_keys)
        report   = GapAnalyser().analyse(evidence, ["GDPR","CCPA","HIPAA"])
        assert len(report.by_status(ControlStatus.GAP)) == 0

    def test_partial_when_some_evidence(self):
        evidence = AuditEvidence("ds-partial", {"lawful_basis_registered": True})
        report   = GapAnalyser().analyse(evidence, ["GDPR"])
        # GDPR-05 needs only lawful_basis_registered → compliant
        compliant_ids = [a.control.control_id for a in report.by_status(ControlStatus.COMPLIANT)]
        assert "GDPR-05" in compliant_ids


class TestReportGenerator:
    def test_markdown_report(self, tmp_path):
        evidence = AuditEvidence("ds-test", {"encryption_at_rest": True})
        report   = GapAnalyser().analyse(evidence, ["GDPR"])
        gen      = ReportGenerator()
        md       = gen.to_markdown(report)
        assert "# Compliance Gap Report" in md
        assert "GAP" in md or "COMPLIANT" in md

    def test_json_report(self, tmp_path):
        import json
        evidence = AuditEvidence("ds-test", {})
        report   = GapAnalyser().analyse(evidence, ["CCPA"])
        gen      = ReportGenerator()
        out      = tmp_path / "report.json"
        gen.to_json(report, out)
        data = json.loads(out.read_text())
        assert data["dataset_id"] == "ds-test"
        assert len(data["assessments"]) > 0


class TestDPIA:
    def test_generate_dpia(self, tmp_path):
        dpia = generate_ml_dpia(
            dataset_id="ds-dpia", dataset_name="Customer Transactions",
            controller="AcmeCorp", dpo_name="Jane Smith",
            purpose="Fraud detection model training",
            data_categories=["email","transaction_history"],
            subject_count=500000,
        )
        assert len(dpia.sections) == 6
        md = dpia.to_markdown()
        assert "Customer Transactions" in md
        assert "Jane Smith" in md

    def test_save_markdown(self, tmp_path):
        dpia = generate_ml_dpia("ds-1","Test DS","Corp","DPO",
                                "Training","["+"name"+"]",100)
        path = tmp_path / "dpia.md"
        dpia.save_markdown(path)
        assert path.exists()
        assert "DRAFT" in path.read_text()
