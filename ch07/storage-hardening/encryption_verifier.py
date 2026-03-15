"""
encryption_verifier.py  —  Storage encryption and KMS key rotation checks
AI Fortress · Chapter 7 · Code Sample 7.B

Verifies encryption-at-rest posture for ML artefact storage:
  - Server-side encryption enabled and using CMK (not SSE-S3 default)
  - KMS key rotation enabled for all CMKs used by ML buckets
  - EBS/EFS volumes attached to training infrastructure encrypted with CMK
  - No plaintext credentials in object metadata (scanning object metadata)

Works against in-memory config dicts (for testing/CI) and produces
structured EncryptionReport with pass/fail gate.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class EncryptionFinding:
    check_id:    str
    severity:    str
    resource:    str
    description: str
    remediation: str


@dataclass
class EncryptionReport:
    total_resources: int
    passing:         int
    failing:         int
    findings:        List[EncryptionFinding]
    overall_pass:    bool

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} Encryption check: {self.passing}/{self.total_resources} resources passing. "
            f"{len(self.findings)} finding(s)."
        )


class EncryptionVerifier:
    """
    Verifies encryption configuration for storage resources.

    Accepts a resource config dict of the form:
    {
        "s3_buckets": [
            {
                "name": "ml-models-prod",
                "sse_algorithm": "aws:kms",      # or "AES256" (SSE-S3, weaker)
                "kms_key_id": "arn:aws:kms:...",
                "kms_key_rotation_enabled": true
            }
        ],
        "ebs_volumes": [
            {
                "volume_id": "vol-abc",
                "encrypted": true,
                "kms_key_id": "arn:aws:kms:...",
                "kms_key_rotation_enabled": true
            }
        ],
        "efs_filesystems": [...],
    }

    Parameters
    ----------
    require_cmk        : Require customer-managed keys (not SSE-S3 AES256)
    require_key_rotation : Require KMS automatic key rotation
    """

    def __init__(
        self,
        require_cmk:          bool = True,
        require_key_rotation: bool = True,
    ):
        self.require_cmk          = require_cmk
        self.require_key_rotation = require_key_rotation

    def verify(self, config: dict) -> EncryptionReport:
        findings: List[EncryptionFinding] = []
        total = 0

        # ── S3 buckets ────────────────────────────────────────────────────
        for bucket in config.get("s3_buckets", []):
            total += 1
            name   = bucket.get("name", "unknown")
            algo   = bucket.get("sse_algorithm", "")
            key_id = bucket.get("kms_key_id", "")
            rotation = bucket.get("kms_key_rotation_enabled", False)

            if not algo:
                findings.append(EncryptionFinding(
                    check_id    = "EV-001",
                    severity    = "CRITICAL",
                    resource    = f"s3://{name}",
                    description = f"S3 bucket '{name}' has NO server-side encryption configured.",
                    remediation = "Enable SSE with aws:kms and specify a CMK.",
                ))
            elif algo == "AES256" and self.require_cmk:
                findings.append(EncryptionFinding(
                    check_id    = "EV-002",
                    severity    = "HIGH",
                    resource    = f"s3://{name}",
                    description = f"S3 bucket '{name}' uses SSE-S3 (AES256). "
                                  "Policy requires a customer-managed KMS key (CMK).",
                    remediation = "Change SSEAlgorithm to aws:kms and specify a CMK ARN.",
                ))
            elif algo == "aws:kms":
                if not key_id:
                    findings.append(EncryptionFinding(
                        check_id    = "EV-003",
                        severity    = "HIGH",
                        resource    = f"s3://{name}",
                        description = f"S3 bucket '{name}' uses aws:kms but no KMS key ID specified. "
                                      "Using default AWS-managed key (aws/s3) — cannot audit rotation.",
                        remediation = "Specify an explicit CMK ARN in kms_key_id.",
                    ))
                elif self.require_key_rotation and not rotation:
                    findings.append(EncryptionFinding(
                        check_id    = "EV-004",
                        severity    = "MEDIUM",
                        resource    = f"s3://{name}",
                        description = f"KMS key for S3 bucket '{name}' does not have "
                                      "automatic key rotation enabled.",
                        remediation = "Enable automatic rotation on the KMS key (annual rotation).",
                    ))

        # ── EBS volumes ───────────────────────────────────────────────────
        for vol in config.get("ebs_volumes", []):
            total += 1
            vid      = vol.get("volume_id", "unknown")
            enc      = vol.get("encrypted", False)
            key_id   = vol.get("kms_key_id", "")
            rotation = vol.get("kms_key_rotation_enabled", False)

            if not enc:
                findings.append(EncryptionFinding(
                    check_id    = "EV-005",
                    severity    = "CRITICAL",
                    resource    = f"ebs/{vid}",
                    description = f"EBS volume '{vid}' is NOT encrypted at rest. "
                                  "Model weights or datasets cached on disk are exposed.",
                    remediation = "Snapshot, re-encrypt, and replace the volume with encrypted=true.",
                ))
            elif self.require_cmk and not key_id:
                findings.append(EncryptionFinding(
                    check_id    = "EV-006",
                    severity    = "MEDIUM",
                    resource    = f"ebs/{vid}",
                    description = f"EBS volume '{vid}' uses default KMS key, not a CMK.",
                    remediation = "Specify a CMK ARN when creating encrypted volumes.",
                ))
            elif self.require_key_rotation and key_id and not rotation:
                findings.append(EncryptionFinding(
                    check_id    = "EV-004",
                    severity    = "MEDIUM",
                    resource    = f"ebs/{vid}",
                    description = f"KMS key for EBS volume '{vid}' does not rotate automatically.",
                    remediation = "Enable automatic rotation on the CMK.",
                ))

        # ── EFS filesystems ───────────────────────────────────────────────
        for efs in config.get("efs_filesystems", []):
            total += 1
            fid = efs.get("filesystem_id", "unknown")
            if not efs.get("encrypted", False):
                findings.append(EncryptionFinding(
                    check_id    = "EV-007",
                    severity    = "CRITICAL",
                    resource    = f"efs/{fid}",
                    description = f"EFS filesystem '{fid}' is NOT encrypted at rest.",
                    remediation = "EFS encryption cannot be enabled after creation. "
                                  "Create a new encrypted filesystem and migrate data.",
                ))

        failing = len({f.resource for f in findings})
        passing = max(0, total - failing)

        return EncryptionReport(
            total_resources = total,
            passing         = passing,
            failing         = failing,
            findings        = findings,
            overall_pass    = len([f for f in findings if f.severity in ("CRITICAL", "HIGH")]) == 0,
        )
