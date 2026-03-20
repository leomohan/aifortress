"""
tests/test_iac_security.py  —  IaC security scanner tests
AI Fortress · Chapter 7 · Code Sample 7.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import json
import pytest
from terraform_scanner import TerraformScanner, Finding
from cfn_scanner import CloudFormationScanner
from policy_enforcer import PolicyEnforcer, PolicyViolationError
from drift_detector import DriftDetector


# ── TerraformScanner ──────────────────────────────────────────────────────────

class TestTerraformScanner:

    def test_open_security_group_detected(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_security_group.ml_sg": {
                "ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22}]
            }
        })
        assert any(f.rule_id == "TF-001" and f.severity == "CRITICAL" for f in findings)

    def test_restricted_sg_no_finding(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_security_group.ml_sg": {
                "ingress": [{"cidr_blocks": ["10.0.0.0/8"], "from_port": 443, "to_port": 443}]
            }
        })
        tf001 = [f for f in findings if f.rule_id == "TF-001"]
        assert len(tf001) == 0

    def test_unencrypted_ebs_detected(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_ebs_volume.data_vol": {"encrypted": False}
        })
        assert any(f.rule_id == "TF-003" and f.severity == "CRITICAL" for f in findings)

    def test_encrypted_ebs_no_finding(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_ebs_volume.data_vol": {"encrypted": True, "kms_key_id": "arn:aws:kms:..."}
        })
        tf003 = [f for f in findings if f.rule_id == "TF-003"]
        assert len(tf003) == 0

    def test_s3_bucket_without_versioning_detected(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_s3_bucket.model_store": {"versioning": [{"enabled": False}]}
        })
        assert any(f.rule_id == "TF-004" for f in findings)

    def test_s3_public_acl_detected(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_s3_bucket_acl.model_acl": {"acl": "public-read"}
        })
        assert any(f.rule_id == "TF-006" and f.severity == "CRITICAL" for f in findings)

    def test_iam_wildcard_detected(self):
        sc = TerraformScanner()
        policy_doc = json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        })
        findings = sc.scan_dict({
            "aws_iam_role_policy.ml_policy": {"policy": policy_doc}
        })
        assert any(f.rule_id == "TF-007" and f.severity == "HIGH" for f in findings)

    def test_public_ec2_detected(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_instance.trainer": {
                "associate_public_ip_address": True,
                "root_block_device": [{"encrypted": True}],
            }
        })
        assert any(f.rule_id == "TF-002" for f in findings)

    def test_missing_tags_detected(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_instance.trainer": {
                "associate_public_ip_address": False,
                "root_block_device": [{"encrypted": True}],
                "tags": {},
            }
        })
        assert any(f.rule_id == "TF-011" and f.severity == "LOW" for f in findings)

    def test_cloudtrail_no_validation_detected(self):
        sc = TerraformScanner()
        findings = sc.scan_dict({
            "aws_cloudtrail.ml_trail": {
                "enable_log_file_validation": False,
                "is_multi_region_trail": True,
            }
        })
        assert any(f.rule_id == "TF-009" for f in findings)

    def test_scan_plan_dict_format(self):
        sc   = TerraformScanner()
        plan = {
            "resource_changes": [
                {
                    "type": "aws_ebs_volume",
                    "name": "gpu_vol",
                    "change": {"after": {"encrypted": False}},
                }
            ]
        }
        findings = sc.scan(plan)
        assert any(f.rule_id == "TF-003" for f in findings)


# ── CloudFormationScanner ─────────────────────────────────────────────────────

class TestCloudFormationScanner:

    def test_open_sg_detected(self):
        sc = CloudFormationScanner()
        template = {
            "Resources": {
                "MLSecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "SecurityGroupIngress": [
                            {"CidrIp": "0.0.0.0/0", "FromPort": 22, "ToPort": 22}
                        ]
                    }
                }
            }
        }
        findings = sc.scan(template)
        assert any(f.rule_id == "CFN-003" and f.severity == "CRITICAL" for f in findings)

    def test_s3_without_versioning_detected(self):
        sc = CloudFormationScanner()
        template = {
            "Resources": {
                "ModelBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"VersioningConfiguration": {"Status": "Suspended"}},
                }
            }
        }
        findings = sc.scan(template)
        assert any(f.rule_id == "CFN-006" for f in findings)

    def test_missing_deletion_policy_detected(self):
        sc = CloudFormationScanner()
        template = {
            "Resources": {
                "DatasetBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "VersioningConfiguration": {"Status": "Enabled"},
                        "BucketEncryption": {"ServerSideEncryptionConfiguration": [{}]},
                    },
                    # No DeletionPolicy
                }
            }
        }
        findings = sc.scan(template)
        assert any(f.rule_id == "CFN-002" for f in findings)

    def test_hardcoded_credential_detected(self):
        sc = CloudFormationScanner()
        template = {
            "Parameters": {
                "DBPassword": {
                    "Type": "String",
                    "Default": "mysecretpassword123",
                }
            },
            "Resources": {}
        }
        findings = sc.scan(template)
        assert any(f.rule_id == "CFN-001" and f.severity == "CRITICAL" for f in findings)

    def test_dynamodb_without_sse_detected(self):
        sc = CloudFormationScanner()
        template = {
            "Resources": {
                "ExperimentTable": {
                    "Type": "AWS::DynamoDB::Table",
                    "DeletionPolicy": "Retain",
                    "Properties": {"SSESpecification": {"SSEEnabled": False}},
                }
            }
        }
        findings = sc.scan(template)
        assert any(f.rule_id == "CFN-009" for f in findings)

    def test_clean_template_no_critical(self):
        sc = CloudFormationScanner()
        template = {
            "Resources": {
                "ModelBucket": {
                    "Type": "AWS::S3::Bucket",
                    "DeletionPolicy": "Retain",
                    "Properties": {
                        "VersioningConfiguration": {"Status": "Enabled"},
                        "BucketEncryption": {"ServerSideEncryptionConfiguration": [
                            {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
                        ]},
                    },
                }
            }
        }
        findings = sc.scan(template)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) == 0


# ── PolicyEnforcer ────────────────────────────────────────────────────────────

class TestPolicyEnforcer:

    def _make_finding(self, severity: str) -> Finding:
        return Finding(
            rule_id="TEST-001", severity=severity,
            resource_type="aws_s3_bucket", resource_name="test",
            description="test", remediation="fix it",
        )

    def test_no_findings_passes(self):
        enforcer = PolicyEnforcer(fail_on_severity="CRITICAL")
        report   = enforcer.enforce([])
        assert report.passed

    def test_critical_finding_raises(self):
        enforcer = PolicyEnforcer(fail_on_severity="CRITICAL")
        with pytest.raises(PolicyViolationError) as exc:
            enforcer.enforce([self._make_finding("CRITICAL")])
        assert exc.value.critical == 1

    def test_high_finding_below_gate_passes(self):
        enforcer = PolicyEnforcer(fail_on_severity="CRITICAL")
        report   = enforcer.enforce([self._make_finding("HIGH")])
        assert report.passed

    def test_high_gate_rejects_high(self):
        enforcer = PolicyEnforcer(fail_on_severity="HIGH")
        with pytest.raises(PolicyViolationError):
            enforcer.enforce([self._make_finding("HIGH")])

    def test_report_counts_accurate(self):
        enforcer = PolicyEnforcer(fail_on_severity="CRITICAL")
        findings = [
            self._make_finding("CRITICAL"),
            self._make_finding("HIGH"),
            self._make_finding("HIGH"),
            self._make_finding("MEDIUM"),
            self._make_finding("LOW"),
        ]
        report = enforcer.build_report(findings)
        assert report.critical == 1
        assert report.high     == 2
        assert report.medium   == 1
        assert report.low      == 1
        assert report.total    == 5

    def test_report_save_json(self, tmp_path):
        enforcer = PolicyEnforcer()
        report   = enforcer.build_report([self._make_finding("LOW")])
        path     = tmp_path / "report.json"
        report.save_json(path)
        data = json.loads(path.read_text())
        assert "findings" in data
        assert data["low"] == 1

    def test_report_save_markdown(self, tmp_path):
        enforcer = PolicyEnforcer()
        report   = enforcer.build_report([self._make_finding("HIGH")])
        path     = tmp_path / "report.md"
        report.save_markdown(path)
        md = path.read_text()
        assert "IaC Security Scan Report" in md


# ── DriftDetector ─────────────────────────────────────────────────────────────

class TestDriftDetector:

    def test_no_drift_clean(self):
        det = DriftDetector()
        state = {"aws_s3_bucket.models": {"versioning": True, "encrypted": True}}
        report = det.detect(state, state.copy())
        assert report.clean
        assert report.total_drift == 0

    def test_shadow_resource_detected(self):
        det = DriftDetector()
        iac      = {"aws_s3_bucket.models": {"versioning": True}}
        deployed = {
            "aws_s3_bucket.models":   {"versioning": True},
            "aws_s3_bucket.rogue":    {"versioning": False},   # shadow
        }
        report = det.detect(iac, deployed)
        assert report.shadow == 1
        shadow_ids = [i.resource_id for i in report.items if i.drift_type == "SHADOW"]
        assert "aws_s3_bucket.rogue" in shadow_ids

    def test_missing_resource_detected(self):
        det = DriftDetector()
        iac      = {
            "aws_s3_bucket.models":  {"versioning": True},
            "aws_cloudtrail.audit":  {"enabled": True},
        }
        deployed = {"aws_s3_bucket.models": {"versioning": True}}
        report   = det.detect(iac, deployed)
        assert report.missing == 1
        missing_ids = [i.resource_id for i in report.items if i.drift_type == "MISSING"]
        assert "aws_cloudtrail.audit" in missing_ids

    def test_changed_attribute_detected(self):
        det = DriftDetector()
        iac      = {"aws_s3_bucket.models": {"versioning": True, "encrypted": True}}
        deployed = {"aws_s3_bucket.models": {"versioning": True, "encrypted": False}}
        report   = det.detect(iac, deployed)
        assert report.changed == 1
        changed = [i for i in report.items if i.drift_type == "CHANGED"]
        assert "encrypted" in changed[0].changed_fields

    def test_ignored_fields_not_flagged(self):
        det = DriftDetector(ignore_fields=["arn", "id", "last_modified"])
        iac      = {"aws_s3_bucket.models": {"versioning": True, "arn": "old-arn"}}
        deployed = {"aws_s3_bucket.models": {"versioning": True, "arn": "new-arn"}}
        report   = det.detect(iac, deployed)
        assert report.clean

    def test_report_save_json(self, tmp_path):
        det    = DriftDetector()
        iac    = {"aws_instance.trainer": {"encrypted": True}}
        dep    = {"aws_instance.trainer": {"encrypted": False}}
        report = det.detect(iac, dep)
        path   = tmp_path / "drift.json"
        report.save_json(path)
        data   = json.loads(path.read_text())
        assert data["changed"] == 1

    def test_summary_string(self):
        det    = DriftDetector()
        iac    = {}
        dep    = {"aws_s3_bucket.rogue": {"versioning": False}}
        report = det.detect(iac, dep)
        assert "shadow" in report.summary().lower()
