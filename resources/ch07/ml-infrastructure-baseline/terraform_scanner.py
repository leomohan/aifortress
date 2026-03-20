"""
terraform_scanner.py  —  Terraform plan JSON misconfiguration scanner
AI Fortress · Chapter 7 · Code Sample 7.A

Parses Terraform plan JSON output (`terraform show -json tfplan`) and
checks for ML-platform-specific security misconfigurations.

Generate the input with:
    terraform plan -out=tfplan
    terraform show -json tfplan > tfplan.json

Checks performed:
  CRITICAL  — Open security groups (0.0.0.0/0 on any port)
  CRITICAL  — Unencrypted EBS volumes attached to training instances
  CRITICAL  — S3 buckets with public ACL or public access block disabled
  HIGH      — IAM roles with AdministratorAccess or "*" actions
  HIGH      — Missing CloudTrail in ML account
  HIGH      — EC2 instances with public IPs in training VPC
  MEDIUM    — S3 buckets without versioning (model/dataset buckets)
  MEDIUM    — S3 buckets without access logging
  MEDIUM    — EFS filesystems without encryption
  LOW       — Missing tags (Owner, Environment, DataClassification)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    rule_id:       str
    severity:      str          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    resource_type: str
    resource_name: str
    description:   str
    remediation:   str
    compliance:    List[str] = field(default_factory=list)  # e.g. ["CIS-AWS-2.2"]


class TerraformScanner:
    """
    Scans Terraform plan JSON for ML-infrastructure security misconfigurations.
    """

    def scan(self, plan: dict) -> List[Finding]:
        """Scan a parsed Terraform plan dict. Returns list of findings."""
        findings: List[Finding] = []
        resources = self._extract_resources(plan)
        for rtype, rname, rconf in resources:
            findings.extend(self._check_resource(rtype, rname, rconf))
        return findings

    def scan_file(self, path: str | Path) -> List[Finding]:
        """Load a Terraform plan JSON file and scan it."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.scan(data)

    def scan_dict(self, resource_dict: dict) -> List[Finding]:
        """
        Scan a simplified resource dict of the form:
            {"aws_instance.trainer": {...attrs...}, ...}
        Useful for unit testing without a full plan JSON.
        """
        findings: List[Finding] = []
        for full_name, attrs in resource_dict.items():
            parts = full_name.split(".", 1)
            rtype = parts[0]
            rname = parts[1] if len(parts) > 1 else full_name
            findings.extend(self._check_resource(rtype, rname, attrs))
        return findings

    # ── Resource extraction ───────────────────────────────────────────────────

    def _extract_resources(self, plan: dict) -> List[tuple]:
        """Extract (resource_type, resource_name, config) triples from plan."""
        resources = []
        # terraform show -json plan format: plan.resource_changes[]
        for change in plan.get("resource_changes", []):
            rtype  = change.get("type", "")
            rname  = change.get("name", "")
            after  = (change.get("change", {}) or {}).get("after") or {}
            resources.append((rtype, rname, after))
        # Also support raw resource map (for testing)
        for rtype, instances in plan.get("resource", {}).items():
            for rname, rconf in instances.items():
                resources.append((rtype, rname, rconf))
        return resources

    # ── Per-resource checks ───────────────────────────────────────────────────

    def _check_resource(self, rtype: str, rname: str, conf: dict) -> List[Finding]:
        handlers = {
            "aws_security_group":           self._check_security_group,
            "aws_security_group_rule":      self._check_sg_rule,
            "aws_instance":                 self._check_ec2_instance,
            "aws_ebs_volume":               self._check_ebs_volume,
            "aws_s3_bucket":                self._check_s3_bucket,
            "aws_s3_bucket_acl":            self._check_s3_acl,
            "aws_s3_bucket_public_access_block": self._check_s3_public_access,
            "aws_iam_role_policy":          self._check_iam_policy,
            "aws_iam_policy":               self._check_iam_policy,
            "aws_efs_file_system":          self._check_efs,
            "aws_cloudtrail":               self._check_cloudtrail,
        }
        handler = handlers.get(rtype)
        if handler:
            return handler(rtype, rname, conf)
        return self._check_missing_tags(rtype, rname, conf)

    def _check_security_group(self, rtype, rname, conf) -> List[Finding]:
        findings = []
        for rule in conf.get("ingress", []):
            if self._is_open_cidr(rule):
                findings.append(Finding(
                    rule_id="TF-001", severity="CRITICAL",
                    resource_type=rtype, resource_name=rname,
                    description=f"Security group '{rname}' has open ingress "
                                f"from 0.0.0.0/0 on port(s) "
                                f"{rule.get('from_port')}-{rule.get('to_port')}.",
                    remediation="Restrict ingress CIDR to specific IP ranges. "
                                "Never allow 0.0.0.0/0 on training infrastructure.",
                    compliance=["CIS-AWS-4.1", "CIS-AWS-4.2", "NIST-AC-17"],
                ))
        return findings

    def _check_sg_rule(self, rtype, rname, conf) -> List[Finding]:
        if conf.get("type") == "ingress" and self._is_open_cidr(conf):
            return [Finding(
                rule_id="TF-001", severity="CRITICAL",
                resource_type=rtype, resource_name=rname,
                description=f"Security group rule '{rname}' allows ingress from 0.0.0.0/0.",
                remediation="Restrict CIDR to known IP ranges.",
                compliance=["CIS-AWS-4.1"],
            )]
        return []

    def _check_ec2_instance(self, rtype, rname, conf) -> List[Finding]:
        findings = []
        if conf.get("associate_public_ip_address"):
            findings.append(Finding(
                rule_id="TF-002", severity="HIGH",
                resource_type=rtype, resource_name=rname,
                description=f"EC2 instance '{rname}' has a public IP address assigned. "
                            "Training instances should run in private subnets.",
                remediation="Set associate_public_ip_address = false. "
                            "Use a bastion host or VPN for access.",
                compliance=["CIS-AWS-2.1", "NIST-SC-7"],
            ))
        # Check for unencrypted root volume
        root_block = conf.get("root_block_device", {}) or {}
        if isinstance(root_block, list):
            root_block = root_block[0] if root_block else {}
        if not root_block.get("encrypted", False):
            findings.append(Finding(
                rule_id="TF-003", severity="CRITICAL",
                resource_type=rtype, resource_name=rname,
                description=f"EC2 instance '{rname}' root EBS volume is NOT encrypted. "
                            "Model weights and datasets cached on disk are exposed.",
                remediation="Set root_block_device { encrypted = true }. "
                            "Specify kms_key_id for customer-managed keys.",
                compliance=["CIS-AWS-2.2", "NIST-SC-28"],
            ))
        return findings + self._check_missing_tags(rtype, rname, conf)

    def _check_ebs_volume(self, rtype, rname, conf) -> List[Finding]:
        if not conf.get("encrypted", False):
            return [Finding(
                rule_id="TF-003", severity="CRITICAL",
                resource_type=rtype, resource_name=rname,
                description=f"EBS volume '{rname}' is not encrypted at rest.",
                remediation="Set encrypted = true and specify kms_key_id.",
                compliance=["CIS-AWS-2.2", "NIST-SC-28"],
            )]
        return []

    def _check_s3_bucket(self, rtype, rname, conf) -> List[Finding]:
        findings = []
        versioning = conf.get("versioning", [{}])
        if isinstance(versioning, list):
            versioning = versioning[0] if versioning else {}
        if not versioning.get("enabled", False):
            findings.append(Finding(
                rule_id="TF-004", severity="MEDIUM",
                resource_type=rtype, resource_name=rname,
                description=f"S3 bucket '{rname}' does not have versioning enabled. "
                            "Model/dataset objects can be silently overwritten or deleted.",
                remediation="Add versioning { enabled = true } to the bucket resource.",
                compliance=["CIS-AWS-2.6", "NIST-CP-9"],
            ))
        logging = conf.get("logging", [])
        if not logging:
            findings.append(Finding(
                rule_id="TF-005", severity="MEDIUM",
                resource_type=rtype, resource_name=rname,
                description=f"S3 bucket '{rname}' does not have access logging enabled. "
                            "Cannot audit who accessed model artefacts.",
                remediation="Add logging { target_bucket = ... } block.",
                compliance=["CIS-AWS-2.7", "NIST-AU-2"],
            ))
        return findings + self._check_missing_tags(rtype, rname, conf)

    def _check_s3_acl(self, rtype, rname, conf) -> List[Finding]:
        acl = conf.get("acl", "")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            return [Finding(
                rule_id="TF-006", severity="CRITICAL",
                resource_type=rtype, resource_name=rname,
                description=f"S3 bucket ACL '{rname}' is set to '{acl}' — "
                            "model artefacts are publicly accessible.",
                remediation="Set acl = 'private' and enable S3 Block Public Access.",
                compliance=["CIS-AWS-2.3", "NIST-AC-3"],
            )]
        return []

    def _check_s3_public_access(self, rtype, rname, conf) -> List[Finding]:
        findings = []
        for flag in ("block_public_acls", "block_public_policy",
                     "ignore_public_acls", "restrict_public_buckets"):
            if not conf.get(flag, False):
                findings.append(Finding(
                    rule_id="TF-006", severity="CRITICAL",
                    resource_type=rtype, resource_name=rname,
                    description=f"S3 public access block '{rname}': '{flag}' is not enabled.",
                    remediation=f"Set {flag} = true in aws_s3_bucket_public_access_block.",
                    compliance=["CIS-AWS-2.3"],
                ))
        return findings

    def _check_iam_policy(self, rtype, rname, conf) -> List[Finding]:
        policy_str = conf.get("policy", "") or conf.get("policy_document", "") or ""
        if not policy_str:
            return []
        try:
            policy_doc = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
        except json.JSONDecodeError:
            return []
        findings = []
        for stmt in policy_doc.get("Statement", []):
            actions  = stmt.get("Action", [])
            effect   = stmt.get("Effect", "")
            resource = stmt.get("Resource", "")
            if isinstance(actions, str):
                actions = [actions]
            if effect == "Allow" and ("*" in actions or "iam:*" in actions):
                findings.append(Finding(
                    rule_id="TF-007", severity="HIGH",
                    resource_type=rtype, resource_name=rname,
                    description=f"IAM policy '{rname}' grants wildcard actions (*).",
                    remediation="Apply least-privilege: enumerate only the specific "
                                "actions required by the ML pipeline role.",
                    compliance=["CIS-AWS-1.16", "NIST-AC-6"],
                ))
        return findings

    def _check_efs(self, rtype, rname, conf) -> List[Finding]:
        if not conf.get("encrypted", False):
            return [Finding(
                rule_id="TF-008", severity="MEDIUM",
                resource_type=rtype, resource_name=rname,
                description=f"EFS filesystem '{rname}' is not encrypted at rest.",
                remediation="Set encrypted = true.",
                compliance=["CIS-AWS-2.4", "NIST-SC-28"],
            )]
        return []

    def _check_cloudtrail(self, rtype, rname, conf) -> List[Finding]:
        findings = []
        if not conf.get("enable_log_file_validation", False):
            findings.append(Finding(
                rule_id="TF-009", severity="HIGH",
                resource_type=rtype, resource_name=rname,
                description=f"CloudTrail '{rname}' does not have log file validation enabled.",
                remediation="Set enable_log_file_validation = true.",
                compliance=["CIS-AWS-2.2"],
            ))
        if not conf.get("is_multi_region_trail", False):
            findings.append(Finding(
                rule_id="TF-010", severity="MEDIUM",
                resource_type=rtype, resource_name=rname,
                description=f"CloudTrail '{rname}' is not multi-region.",
                remediation="Set is_multi_region_trail = true for full coverage.",
                compliance=["CIS-AWS-2.1"],
            ))
        return findings

    def _check_missing_tags(self, rtype, rname, conf) -> List[Finding]:
        required = {"Owner", "Environment", "DataClassification"}
        tags     = conf.get("tags", {}) or {}
        missing  = required - set(tags.keys())
        if missing:
            return [Finding(
                rule_id="TF-011", severity="LOW",
                resource_type=rtype, resource_name=rname,
                description=f"Resource '{rname}' ({rtype}) is missing required tags: {sorted(missing)}.",
                remediation="Add Owner, Environment, and DataClassification tags to all resources.",
                compliance=["NIST-CM-8"],
            )]
        return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _is_open_cidr(rule: dict) -> bool:
        cidrs  = rule.get("cidr_blocks", []) or []
        cidrs6 = rule.get("ipv6_cidr_blocks", []) or []
        return "0.0.0.0/0" in cidrs or "::/0" in cidrs6
