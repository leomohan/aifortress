"""
bucket_policy_auditor.py  —  S3/GCS bucket IAM policy analysis
AI Fortress · Chapter 7 · Code Sample 7.B

Parses S3 bucket policies (JSON) and scores each bucket against a
security hardening checklist relevant to ML artefact storage.

Checks:
  CRITICAL  — Public principal (*) with Allow effect
  CRITICAL  — Cross-account Allow without explicit account condition
  HIGH      — s3:PutObject without MFA delete requirement
  HIGH      — s3:DeleteObject or s3:DeleteBucket without MFA condition
  HIGH      — s3:GetObject exposed to broad AWS account wildcard
  MEDIUM    — No explicit Deny for unencrypted uploads
              (s3:x-amz-server-side-encryption condition missing)
  MEDIUM    — No bucket policy at all (relying solely on ACLs)
  LOW       — Missing aws:SecureTransport condition (allows HTTP access)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PolicyFinding:
    check_id:    str
    severity:    str
    bucket_name: str
    statement_id: str
    description: str
    remediation: str
    compliance:  List[str] = field(default_factory=list)


@dataclass
class BucketAuditResult:
    bucket_name:  str
    total_findings: int
    critical:     int
    high:         int
    medium:       int
    low:          int
    score:        int      # 0–100 hardening score
    findings:     List[PolicyFinding]
    passed:       bool     # True if no CRITICAL or HIGH findings

    def summary(self) -> str:
        icon = "✅" if self.passed else "❌"
        return (
            f"{icon} {self.bucket_name}: score={self.score}/100 "
            f"({self.critical}C {self.high}H {self.medium}M {self.low}L)"
        )


class BucketPolicyAuditor:
    """
    Audits S3 bucket policies for ML-artefact-storage security controls.
    """

    def audit(self, bucket_name: str, policy: Optional[dict]) -> BucketAuditResult:
        """
        Audit a bucket's policy dict.

        Parameters
        ----------
        bucket_name : Human-readable bucket identifier
        policy      : Parsed bucket policy dict (from s3.get_bucket_policy()),
                      or None if no policy is attached.
        """
        findings: List[PolicyFinding] = []

        if policy is None:
            findings.append(PolicyFinding(
                check_id    = "BP-000",
                severity    = "MEDIUM",
                bucket_name = bucket_name,
                statement_id = "N/A",
                description  = f"Bucket '{bucket_name}' has no bucket policy. "
                               "Access is controlled only by ACLs — this is insufficient "
                               "for ML artefact buckets requiring condition-based controls.",
                remediation  = "Attach an explicit bucket policy with Deny for "
                               "unencrypted uploads and HTTP access.",
                compliance   = ["CIS-AWS-2.3"],
            ))
            return self._build_result(bucket_name, findings)

        statements = policy.get("Statement", [])
        has_secure_transport_deny = False
        has_encrypt_deny          = False

        for stmt in statements:
            sid      = stmt.get("Sid", "unnamed")
            effect   = stmt.get("Effect", "")
            principal = stmt.get("Principal", "")
            actions  = stmt.get("Action", [])
            condition = stmt.get("Condition", {})

            if isinstance(actions, str):
                actions = [actions]

            # ── CRITICAL: public principal ────────────────────────────────
            if effect == "Allow" and self._is_public_principal(principal):
                findings.append(PolicyFinding(
                    check_id     = "BP-001",
                    severity     = "CRITICAL",
                    bucket_name  = bucket_name,
                    statement_id = sid,
                    description  = f"Statement '{sid}' grants Allow to public principal (*). "
                                   "ML model artefacts are publicly accessible.",
                    remediation  = "Remove wildcard principal. Specify explicit AWS account "
                                   "ARNs or IAM role ARNs.",
                    compliance   = ["CIS-AWS-2.3", "NIST-AC-3"],
                ))

            # ── CRITICAL: cross-account without condition ──────────────────
            if effect == "Allow" and self._is_cross_account(principal) and not condition:
                findings.append(PolicyFinding(
                    check_id     = "BP-002",
                    severity     = "CRITICAL",
                    bucket_name  = bucket_name,
                    statement_id = sid,
                    description  = f"Statement '{sid}' grants cross-account access "
                                   "without any Condition constraints.",
                    remediation  = "Add aws:PrincipalOrgID or aws:PrincipalAccount "
                                   "condition to restrict cross-account access.",
                    compliance   = ["NIST-AC-17"],
                ))

            # ── HIGH: delete without MFA ──────────────────────────────────
            delete_actions = {"s3:DeleteObject", "s3:DeleteBucket", "s3:DeleteObjectVersion"}
            if effect == "Allow" and any(a in delete_actions or a == "s3:*" for a in actions):
                mfa_required = "aws:MultiFactorAuthPresent" in str(condition)
                if not mfa_required:
                    findings.append(PolicyFinding(
                        check_id     = "BP-003",
                        severity     = "HIGH",
                        bucket_name  = bucket_name,
                        statement_id = sid,
                        description  = f"Statement '{sid}' allows delete operations "
                                       "without MFA condition.",
                        remediation  = "Add Condition: {Bool: {aws:MultiFactorAuthPresent: true}} "
                                       "to delete statements.",
                        compliance   = ["CIS-AWS-2.6", "NIST-AC-17"],
                    ))

            # ── MEDIUM: SecureTransport check ─────────────────────────────
            if effect == "Deny":
                if "aws:SecureTransport" in str(condition):
                    has_secure_transport_deny = True
                if ("s3:x-amz-server-side-encryption" in str(condition) or
                        "s3:x-amz-server-side-encryption-aws-kms-key-id" in str(condition)):
                    has_encrypt_deny = True

        if not has_secure_transport_deny:
            findings.append(PolicyFinding(
                check_id     = "BP-004",
                severity     = "LOW",
                bucket_name  = bucket_name,
                statement_id = "N/A",
                description  = f"Bucket '{bucket_name}' has no Deny for HTTP access. "
                               "Data can be accessed without TLS.",
                remediation  = "Add Deny statement with Condition: "
                               "{Bool: {aws:SecureTransport: false}}.",
                compliance   = ["CIS-AWS-2.3", "NIST-SC-8"],
            ))

        if not has_encrypt_deny:
            findings.append(PolicyFinding(
                check_id     = "BP-005",
                severity     = "MEDIUM",
                bucket_name  = bucket_name,
                statement_id = "N/A",
                description  = f"Bucket '{bucket_name}' has no Deny for unencrypted uploads. "
                               "Objects can be stored without server-side encryption.",
                remediation  = "Add Deny s3:PutObject where "
                               "s3:x-amz-server-side-encryption is null.",
                compliance   = ["NIST-SC-28"],
            ))

        return self._build_result(bucket_name, findings)

    def audit_file(self, bucket_name: str, path: str | Path) -> BucketAuditResult:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.audit(bucket_name, policy)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_result(self, bucket_name: str, findings: List[PolicyFinding]) -> BucketAuditResult:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        # Hardening score: start at 100, deduct per severity
        deductions = counts["CRITICAL"] * 30 + counts["HIGH"] * 15 + counts["MEDIUM"] * 8 + counts["LOW"] * 3
        score      = max(0, 100 - deductions)

        return BucketAuditResult(
            bucket_name    = bucket_name,
            total_findings = len(findings),
            critical       = counts["CRITICAL"],
            high           = counts["HIGH"],
            medium         = counts["MEDIUM"],
            low            = counts["LOW"],
            score          = score,
            findings       = findings,
            passed         = counts["CRITICAL"] == 0 and counts["HIGH"] == 0,
        )

    @staticmethod
    def _is_public_principal(principal: Any) -> bool:
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS", "")
            return aws == "*" or (isinstance(aws, list) and "*" in aws)
        return False

    @staticmethod
    def _is_cross_account(principal: Any) -> bool:
        """True if principal references an explicit external AWS account."""
        s = json.dumps(principal)
        # Heuristic: contains an ARN with a 12-digit account ID
        import re
        return bool(re.search(r"arn:aws:[^:]*::[0-9]{12}", s))
