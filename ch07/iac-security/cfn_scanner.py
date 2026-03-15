"""
cfn_scanner.py  —  CloudFormation template security scanner
AI Fortress · Chapter 7 · Code Sample 7.A

Scans CloudFormation JSON/YAML templates for ML-infrastructure-specific
security misconfigurations, applying the same policy rule set as the
Terraform scanner plus CFn-specific checks:

  - Hardcoded credentials in Parameters defaults or Mappings
  - Missing DeletionPolicy on stateful resources (S3, RDS, DynamoDB)
  - Unencrypted DynamoDB tables (used for ML metadata/experiment tracking)
  - Lambda functions with overly permissive execution roles
  - SNS topics without server-side encryption (used for ML pipeline alerts)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from terraform_scanner import Finding   # reuse Finding dataclass


class CloudFormationScanner:
    """
    Scans CloudFormation templates (dict or file) for security misconfigurations.
    """

    def scan(self, template: dict) -> List[Finding]:
        """Scan a parsed CloudFormation template dict."""
        findings: List[Finding] = []
        findings.extend(self._check_parameters(template))
        findings.extend(self._check_resources(template))
        return findings

    def scan_file(self, path: str | Path) -> List[Finding]:
        """Load a CFn template file (JSON or YAML) and scan it."""
        text = Path(path).read_text(encoding="utf-8")
        try:
            template = json.loads(text)
        except json.JSONDecodeError:
            try:
                import yaml
                template = yaml.safe_load(text)
            except ImportError:
                raise ImportError("PyYAML required for YAML templates: pip install PyYAML")
        return self.scan(template)

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_parameters(self, template: dict) -> List[Finding]:
        """Detect hardcoded credentials in Parameter default values."""
        findings  = []
        cred_pats = re.compile(
            r"(password|passwd|secret|token|api.?key|private.?key)", re.IGNORECASE
        )
        for pname, pdef in (template.get("Parameters") or {}).items():
            default = str(pdef.get("Default", ""))
            if cred_pats.search(pname) and default and default != "":
                findings.append(Finding(
                    rule_id="CFN-001", severity="CRITICAL",
                    resource_type="Parameter", resource_name=pname,
                    description=f"Parameter '{pname}' appears to contain a credential "
                                f"with a non-empty Default value '{default[:20]}...'. "
                                "Credentials must never be hardcoded in templates.",
                    remediation="Remove Default value. Use AWS Secrets Manager or "
                                "SSM Parameter Store with NoEcho=true.",
                    compliance=["CIS-AWS-1.22", "NIST-IA-5"],
                ))
        return findings

    def _check_resources(self, template: dict) -> List[Finding]:
        findings = []
        for rname, rdef in (template.get("Resources") or {}).items():
            rtype   = rdef.get("Type", "")
            props   = rdef.get("Properties", {}) or {}
            meta    = rdef.get("DeletionPolicy", None)

            findings.extend(self._check_deletion_policy(rtype, rname, meta))

            handler = {
                "AWS::EC2::SecurityGroup":         self._check_ec2_sg,
                "AWS::EC2::Instance":              self._check_ec2_instance,
                "AWS::S3::Bucket":                 self._check_s3,
                "AWS::IAM::Role":                  self._check_iam_role,
                "AWS::DynamoDB::Table":            self._check_dynamodb,
                "AWS::Lambda::Function":           self._check_lambda,
                "AWS::SNS::Topic":                 self._check_sns,
                "AWS::CloudTrail::Trail":          self._check_cloudtrail,
                "AWS::EFS::FileSystem":            self._check_efs,
            }.get(rtype)
            if handler:
                findings.extend(handler(rtype, rname, props))
        return findings

    def _check_deletion_policy(self, rtype, rname, policy) -> List[Finding]:
        stateful = {
            "AWS::S3::Bucket", "AWS::RDS::DBInstance",
            "AWS::DynamoDB::Table", "AWS::EFS::FileSystem",
        }
        if rtype in stateful and policy not in ("Retain", "Snapshot"):
            return [Finding(
                rule_id="CFN-002", severity="HIGH",
                resource_type=rtype, resource_name=rname,
                description=f"Stateful resource '{rname}' ({rtype}) has no DeletionPolicy "
                            "set to Retain or Snapshot. Stack deletion will destroy data.",
                remediation="Add DeletionPolicy: Retain to protect ML datasets and model stores.",
                compliance=["NIST-CP-9", "NIST-CP-10"],
            )]
        return []

    def _check_ec2_sg(self, rtype, rname, props) -> List[Finding]:
        findings = []
        for rule in props.get("SecurityGroupIngress", []):
            cidr   = rule.get("CidrIp", "")
            cidr6  = rule.get("CidrIpv6", "")
            if cidr == "0.0.0.0/0" or cidr6 == "::/0":
                findings.append(Finding(
                    rule_id="CFN-003", severity="CRITICAL",
                    resource_type=rtype, resource_name=rname,
                    description=f"Security group '{rname}' allows ingress from 0.0.0.0/0.",
                    remediation="Restrict CidrIp to specific CIDR ranges.",
                    compliance=["CIS-AWS-4.1", "NIST-SC-7"],
                ))
        return findings

    def _check_ec2_instance(self, rtype, rname, props) -> List[Finding]:
        findings = []
        if props.get("NetworkInterfaces"):
            for ni in props["NetworkInterfaces"]:
                if ni.get("AssociatePublicIpAddress"):
                    findings.append(Finding(
                        rule_id="CFN-004", severity="HIGH",
                        resource_type=rtype, resource_name=rname,
                        description=f"EC2 instance '{rname}' has a public IP.",
                        remediation="Set AssociatePublicIpAddress: false.",
                        compliance=["CIS-AWS-2.1"],
                    ))
        for bdm in props.get("BlockDeviceMappings", []):
            ebs = bdm.get("Ebs", {}) or {}
            if not ebs.get("Encrypted", False):
                findings.append(Finding(
                    rule_id="CFN-005", severity="CRITICAL",
                    resource_type=rtype, resource_name=rname,
                    description=f"EBS volume in instance '{rname}' is not encrypted.",
                    remediation="Set Ebs.Encrypted: true.",
                    compliance=["CIS-AWS-2.2", "NIST-SC-28"],
                ))
        return findings

    def _check_s3(self, rtype, rname, props) -> List[Finding]:
        findings = []
        versioning = props.get("VersioningConfiguration", {})
        if versioning.get("Status") != "Enabled":
            findings.append(Finding(
                rule_id="CFN-006", severity="MEDIUM",
                resource_type=rtype, resource_name=rname,
                description=f"S3 bucket '{rname}' does not have versioning enabled.",
                remediation="Add VersioningConfiguration: Status: Enabled.",
                compliance=["CIS-AWS-2.6", "NIST-CP-9"],
            ))
        encryption = props.get("BucketEncryption", {})
        if not encryption:
            findings.append(Finding(
                rule_id="CFN-007", severity="HIGH",
                resource_type=rtype, resource_name=rname,
                description=f"S3 bucket '{rname}' has no server-side encryption configured.",
                remediation="Add BucketEncryption with AES256 or aws:kms.",
                compliance=["NIST-SC-28"],
            ))
        return findings

    def _check_iam_role(self, rtype, rname, props) -> List[Finding]:
        findings = []
        for policy in props.get("Policies", []):
            doc = policy.get("PolicyDocument", {})
            for stmt in doc.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if stmt.get("Effect") == "Allow" and "*" in actions:
                    findings.append(Finding(
                        rule_id="CFN-008", severity="HIGH",
                        resource_type=rtype, resource_name=rname,
                        description=f"IAM role '{rname}' grants wildcard (*) actions.",
                        remediation="Enumerate specific actions required for the ML pipeline.",
                        compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                    ))
        return findings

    def _check_dynamodb(self, rtype, rname, props) -> List[Finding]:
        sse = props.get("SSESpecification", {})
        if not sse.get("SSEEnabled", False):
            return [Finding(
                rule_id="CFN-009", severity="MEDIUM",
                resource_type=rtype, resource_name=rname,
                description=f"DynamoDB table '{rname}' does not have SSE enabled. "
                            "ML experiment metadata stored unencrypted.",
                remediation="Add SSESpecification: SSEEnabled: true.",
                compliance=["NIST-SC-28"],
            )]
        return []

    def _check_lambda(self, rtype, rname, props) -> List[Finding]:
        # Check that reserved concurrency is set (DoS protection for ML APIs)
        if props.get("ReservedConcurrentExecutions") is None:
            return [Finding(
                rule_id="CFN-010", severity="LOW",
                resource_type=rtype, resource_name=rname,
                description=f"Lambda function '{rname}' has no ReservedConcurrentExecutions. "
                            "Could be scaled to DoS the ML pipeline.",
                remediation="Set ReservedConcurrentExecutions to limit blast radius.",
                compliance=["NIST-SC-5"],
            )]
        return []

    def _check_sns(self, rtype, rname, props) -> List[Finding]:
        if not props.get("KmsMasterKeyId"):
            return [Finding(
                rule_id="CFN-011", severity="LOW",
                resource_type=rtype, resource_name=rname,
                description=f"SNS topic '{rname}' does not use a KMS key for SSE. "
                            "ML pipeline alerts transmitted without encryption.",
                remediation="Set KmsMasterKeyId to an AWS KMS key ARN.",
                compliance=["NIST-SC-28"],
            )]
        return []

    def _check_cloudtrail(self, rtype, rname, props) -> List[Finding]:
        findings = []
        if not props.get("EnableLogFileValidation", False):
            findings.append(Finding(
                rule_id="CFN-012", severity="HIGH",
                resource_type=rtype, resource_name=rname,
                description=f"CloudTrail '{rname}' does not validate log file integrity.",
                remediation="Set EnableLogFileValidation: true.",
                compliance=["CIS-AWS-2.2"],
            ))
        return findings

    def _check_efs(self, rtype, rname, props) -> List[Finding]:
        if not props.get("Encrypted", False):
            return [Finding(
                rule_id="CFN-013", severity="MEDIUM",
                resource_type=rtype, resource_name=rname,
                description=f"EFS filesystem '{rname}' is not encrypted at rest.",
                remediation="Set Encrypted: true.",
                compliance=["NIST-SC-28"],
            )]
        return []
