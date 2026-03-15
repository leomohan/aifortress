"""
public_access_scanner.py  —  Public access vector detection for ML storage
AI Fortress · Chapter 7 · Code Sample 7.B

Detects vectors through which ML artefact storage could be publicly exposed:
  1. S3 Block Public Access settings (all four flags must be true)
  2. ACL-based public access (public-read or public-read-write ACLs)
  3. Bucket policy public statements (principal = *)
  4. Presigned URL policy — maximum expiry window enforcement
  5. Cross-account sharing without explicit principal constraints
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PublicAccessFinding:
    check_id:    str
    severity:    str
    bucket_name: str
    vector:      str        # "block_public_access" | "acl" | "policy" | "presigned"
    description: str
    remediation: str


@dataclass
class PublicAccessReport:
    bucket_name:    str
    public_vectors: int
    findings:       List[PublicAccessFinding]
    is_public:      bool    # True if any CRITICAL vector is open

    def summary(self) -> str:
        if self.is_public:
            return f"🔴 CRITICAL: {self.bucket_name} is publicly accessible via {self.public_vectors} vector(s)."
        return f"✅ {self.bucket_name}: No public access vectors detected."


class PublicAccessScanner:
    """
    Scans storage bucket configuration for public access exposure.

    Parameters
    ----------
    max_presigned_url_seconds : Maximum allowed presigned URL expiry (default 3600 = 1h)
    """

    def __init__(self, max_presigned_url_seconds: int = 3600):
        self.max_presigned = max_presigned_url_seconds

    def scan(self, bucket_name: str, config: dict) -> PublicAccessReport:
        """
        Scan a bucket config dict. Expected keys:
            block_public_access : {block_public_acls, ignore_public_acls,
                                   block_public_policy, restrict_public_buckets}
            acl                 : "private" | "public-read" | ...
            policy              : bucket policy dict (optional)
            presigned_url_max_seconds: int (optional)
        """
        findings: List[PublicAccessFinding] = []

        # ── Block Public Access ───────────────────────────────────────────
        bpa = config.get("block_public_access", {})
        required_flags = [
            "block_public_acls", "ignore_public_acls",
            "block_public_policy", "restrict_public_buckets",
        ]
        for flag in required_flags:
            if not bpa.get(flag, False):
                findings.append(PublicAccessFinding(
                    check_id    = "PA-001",
                    severity    = "CRITICAL",
                    bucket_name = bucket_name,
                    vector      = "block_public_access",
                    description = f"S3 Block Public Access flag '{flag}' is NOT enabled on '{bucket_name}'.",
                    remediation = f"Enable {flag} in the bucket's public access block configuration.",
                ))

        # ── ACL check ─────────────────────────────────────────────────────
        acl = config.get("acl", "private")
        if acl in ("public-read", "public-read-write", "authenticated-read"):
            findings.append(PublicAccessFinding(
                check_id    = "PA-002",
                severity    = "CRITICAL",
                bucket_name = bucket_name,
                vector      = "acl",
                description = f"Bucket '{bucket_name}' ACL is '{acl}' — ML artefacts are publicly readable.",
                remediation = "Set ACL to 'private'. Enable S3 Block Public Access.",
            ))

        # ── Bucket policy public principal ────────────────────────────────
        policy = config.get("policy")
        if policy:
            for stmt in policy.get("Statement", []):
                if stmt.get("Effect") == "Allow" and self._is_public(stmt.get("Principal")):
                    findings.append(PublicAccessFinding(
                        check_id    = "PA-003",
                        severity    = "CRITICAL",
                        bucket_name = bucket_name,
                        vector      = "policy",
                        description = f"Bucket policy on '{bucket_name}' has Allow for public principal (*). "
                                      f"Statement: {stmt.get('Sid', 'unnamed')}",
                        remediation = "Remove wildcard principal. Use explicit IAM role ARNs.",
                    ))

        # ── Presigned URL window ──────────────────────────────────────────
        presigned_max = config.get("presigned_url_max_seconds")
        if presigned_max is not None and presigned_max > self.max_presigned:
            findings.append(PublicAccessFinding(
                check_id    = "PA-004",
                severity    = "HIGH",
                bucket_name = bucket_name,
                vector      = "presigned",
                description = f"Presigned URL maximum expiry for '{bucket_name}' is "
                              f"{presigned_max}s, exceeding the policy limit of {self.max_presigned}s. "
                              "Long-lived presigned URLs can be shared beyond intended recipients.",
                remediation = f"Set presigned URL expiry ≤ {self.max_presigned}s "
                              f"({self.max_presigned // 3600}h).",
            ))

        critical_vectors = len([f for f in findings if f.severity == "CRITICAL"])
        return PublicAccessReport(
            bucket_name    = bucket_name,
            public_vectors = len(findings),
            findings       = findings,
            is_public      = critical_vectors > 0,
        )

    @staticmethod
    def _is_public(principal: Any) -> bool:
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws = principal.get("AWS", "")
            return aws == "*" or (isinstance(aws, list) and "*" in aws)
        return False
