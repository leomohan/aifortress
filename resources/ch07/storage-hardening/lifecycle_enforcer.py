"""
lifecycle_enforcer.py  —  Versioning and lifecycle rule enforcement
AI Fortress · Chapter 7 · Code Sample 7.B

Verifies that S3 buckets used for ML artefacts have:
  1. Versioning enabled — required to detect silent overwrites/deletions
  2. Lifecycle rules configured — to transition and expire old versions,
     controlling both cost and attack surface
  3. Noncurrent version expiration — old model versions don't accumulate
     indefinitely in an uncontrolled way

Also generates a compliant lifecycle policy for ML artefact buckets
with configurable retention tiers.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class LifecycleFinding:
    check_id:    str
    severity:    str
    bucket_name: str
    description: str
    remediation: str


@dataclass
class LifecycleReport:
    bucket_name:     str
    versioning_ok:   bool
    lifecycle_ok:    bool
    findings:        List[LifecycleFinding]
    overall_pass:    bool

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} {self.bucket_name}: versioning={'✓' if self.versioning_ok else '✗'}, "
            f"lifecycle={'✓' if self.lifecycle_ok else '✗'} "
            f"({len(self.findings)} finding(s))"
        )


class LifecycleEnforcer:
    """
    Enforces versioning and lifecycle rules on ML artefact buckets.

    Parameters
    ----------
    require_noncurrent_expiry_days : Max days to retain noncurrent versions (default 90)
    require_transition_to_ia_days  : Days before transitioning to STANDARD_IA (default 30)
    require_transition_to_glacier_days : Days before moving to Glacier (default 180)
    """

    def __init__(
        self,
        require_noncurrent_expiry_days:      int = 90,
        require_transition_to_ia_days:       int = 30,
        require_transition_to_glacier_days:  int = 180,
    ):
        self.noncurrent_expiry_days   = require_noncurrent_expiry_days
        self.ia_transition_days       = require_transition_to_ia_days
        self.glacier_transition_days  = require_transition_to_glacier_days

    def check(self, bucket_name: str, config: dict) -> LifecycleReport:
        """
        Check a bucket config dict. Expected keys:
            versioning              : {"status": "Enabled" | "Suspended" | ""}
            lifecycle_rules         : list of S3 lifecycle rule dicts
        """
        findings: List[LifecycleFinding] = []

        # ── Versioning ────────────────────────────────────────────────────
        versioning = config.get("versioning", {})
        versioning_ok = versioning.get("status", "") == "Enabled"
        if not versioning_ok:
            findings.append(LifecycleFinding(
                check_id    = "LC-001",
                severity    = "HIGH",
                bucket_name = bucket_name,
                description = f"Bucket '{bucket_name}' does not have versioning enabled "
                              f"(status='{versioning.get('status', 'not set')}').",
                remediation = "Enable versioning: aws s3api put-bucket-versioning "
                              "--bucket <name> --versioning-configuration Status=Enabled",
            ))

        # ── Lifecycle rules ───────────────────────────────────────────────
        rules = config.get("lifecycle_rules", [])
        lifecycle_ok = bool(rules)

        if not rules:
            findings.append(LifecycleFinding(
                check_id    = "LC-002",
                severity    = "MEDIUM",
                bucket_name = bucket_name,
                description = f"Bucket '{bucket_name}' has no lifecycle rules configured. "
                              "Noncurrent versions will accumulate indefinitely.",
                remediation = "Add lifecycle rules for IA transition, Glacier archival, "
                              "and noncurrent version expiration.",
            ))
        else:
            # Check for noncurrent version expiration rule
            has_noncurrent_expiry = any(
                r.get("noncurrent_version_expiration", {}).get("noncurrent_days", 0) > 0
                or r.get("NoncurrentVersionExpiration", {}).get("NoncurrentDays", 0) > 0
                for r in rules
            )
            if not has_noncurrent_expiry:
                findings.append(LifecycleFinding(
                    check_id    = "LC-003",
                    severity    = "MEDIUM",
                    bucket_name = bucket_name,
                    description = f"Bucket '{bucket_name}' has no noncurrent version expiration rule. "
                                  "Old model versions accumulate without bound.",
                    remediation = f"Add NoncurrentVersionExpiration with NoncurrentDays="
                                  f"{self.noncurrent_expiry_days}.",
                ))

            # Check for IA transition
            has_ia = any(
                any(t.get("storage_class") in ("STANDARD_IA", "ONEZONE_IA") or
                    t.get("StorageClass") in ("STANDARD_IA", "ONEZONE_IA")
                    for t in (r.get("transitions", []) or r.get("Transitions", [])))
                for r in rules
            )
            if not has_ia:
                findings.append(LifecycleFinding(
                    check_id    = "LC-004",
                    severity    = "LOW",
                    bucket_name = bucket_name,
                    description = f"Bucket '{bucket_name}' has no transition to STANDARD_IA. "
                                  "Older model versions remain in expensive HOT storage.",
                    remediation = f"Add transition to STANDARD_IA after {self.ia_transition_days} days.",
                ))

        overall = len([f for f in findings if f.severity in ("CRITICAL", "HIGH")]) == 0
        return LifecycleReport(
            bucket_name  = bucket_name,
            versioning_ok = versioning_ok,
            lifecycle_ok  = lifecycle_ok,
            findings      = findings,
            overall_pass  = overall,
        )

    def generate_policy(self, bucket_name: str, prefix: str = "") -> dict:
        """
        Generate a compliant S3 lifecycle policy for an ML artefact bucket.
        Returns a dict suitable for use as the LifecycleConfiguration argument.
        """
        filter_cfg = {"Prefix": prefix} if prefix else {}
        return {
            "Rules": [
                {
                    "ID":     f"{bucket_name}-ia-transition",
                    "Status": "Enabled",
                    "Filter": filter_cfg,
                    "Transitions": [
                        {"Days": self.ia_transition_days,      "StorageClass": "STANDARD_IA"},
                        {"Days": self.glacier_transition_days, "StorageClass": "GLACIER"},
                    ],
                    "NoncurrentVersionTransitions": [
                        {"NoncurrentDays": self.ia_transition_days, "StorageClass": "STANDARD_IA"},
                    ],
                    "NoncurrentVersionExpiration": {
                        "NoncurrentDays": self.noncurrent_expiry_days,
                    },
                    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
                }
            ]
        }
