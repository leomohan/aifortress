"""
runbook_generator.py  —  DR runbook generation (Markdown + JSON)
AI Fortress · Chapter 7 · Code Sample 7.C

Generates a machine-readable Disaster Recovery runbook for an ML platform,
covering:
  - Asset inventory (what needs to be recovered and where backups live)
  - RTO/RPO targets per tier
  - Step-by-step restoration procedures
  - Escalation contacts
  - Tabletop exercise checklist
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from backup_scheduler import BackupSchedule


@dataclass
class EscalationContact:
    name:        str
    role:        str
    email:       str
    phone:       str = ""
    on_call_url: str = ""


@dataclass
class DRRunbook:
    runbook_id:   str
    platform:     str
    generated_at: str
    rto_seconds:  Dict[str, int]    # tier_name → RTO in seconds
    rpo_seconds:  Dict[str, int]    # tier_name → RPO in seconds
    schedules:    List[BackupSchedule]
    contacts:     List[EscalationContact]
    procedures:   List[dict]        # ordered restoration steps
    tabletop:     List[str]         # exercise scenario checklist items

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def save_markdown(self, path: str | Path) -> None:
        Path(path).write_text(self._to_markdown(), encoding="utf-8")

    def _to_markdown(self) -> str:
        lines = [
            f"# Disaster Recovery Runbook — {self.platform}",
            f"**Runbook ID:** `{self.runbook_id}`  ",
            f"**Generated:** {self.generated_at}",
            "",
            "---",
            "",
            "## 1. RTO / RPO Targets",
            "",
            "| Tier | RTO | RPO |",
            "|------|-----|-----|",
        ]
        tiers = sorted(set(list(self.rto_seconds.keys()) + list(self.rpo_seconds.keys())))
        for t in tiers:
            rto = self.rto_seconds.get(t, 0)
            rpo = self.rpo_seconds.get(t, 0)
            lines.append(
                f"| {t} | {self._fmt_seconds(rto)} | {self._fmt_seconds(rpo)} |"
            )

        lines += ["", "---", "", "## 2. Protected Assets", ""]
        for s in self.schedules:
            lines.append(
                f"- **{s.name}** (`{s.resource_id}`, {s.resource_type}) — "
                f"Tier {s.tier}, RPO={self._fmt_seconds(s.rpo_seconds)}, "
                f"Destination: `{s.destination}`"
            )

        lines += ["", "---", "", "## 3. Restoration Procedures", ""]
        for i, proc in enumerate(self.procedures, 1):
            lines.append(f"### Step {i}: {proc.get('title', 'Unnamed Step')}")
            lines.append(proc.get("description", ""))
            if proc.get("commands"):
                lines.append("")
                lines.append("```bash")
                for cmd in proc["commands"]:
                    lines.append(cmd)
                lines.append("```")
            lines.append("")

        lines += ["---", "", "## 4. Escalation Contacts", ""]
        for c in self.contacts:
            lines.append(f"- **{c.name}** ({c.role}) — {c.email}")

        lines += ["", "---", "", "## 5. Tabletop Exercise Checklist", ""]
        for item in self.tabletop:
            lines.append(f"- [ ] {item}")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _fmt_seconds(s: int) -> str:
        if s >= 3600:
            return f"{s // 3600}h"
        if s >= 60:
            return f"{s // 60}m"
        return f"{s}s"


class RunbookGenerator:
    """
    Generates a DR runbook from a set of backup schedules and platform config.
    """

    def generate(
        self,
        platform:     str,
        schedules:    List[BackupSchedule],
        contacts:     List[EscalationContact],
        rto_by_tier:  Optional[Dict[str, int]] = None,
    ) -> DRRunbook:
        """
        Generate a DRRunbook.

        Parameters
        ----------
        platform    : Platform / system name (e.g. "ML Platform Prod")
        schedules   : List of BackupSchedule objects
        contacts    : Escalation contacts in priority order
        rto_by_tier : Optional RTO override per tier name;
                      defaults to 4× the tier's RPO
        """
        rpo_by_tier = {s.name: s.rpo_seconds for s in schedules}
        rto_final   = {}
        rpo_final   = {}
        for s in schedules:
            rpo_final[s.name] = s.rpo_seconds
            if rto_by_tier and s.name in rto_by_tier:
                rto_final[s.name] = rto_by_tier[s.name]
            else:
                rto_final[s.name] = s.rpo_seconds * 4   # default RTO = 4× RPO

        procedures = self._build_procedures(schedules)
        tabletop   = self._build_tabletop(schedules, platform)

        return DRRunbook(
            runbook_id   = str(uuid.uuid4()),
            platform     = platform,
            generated_at = datetime.now(timezone.utc).isoformat(),
            rto_seconds  = rto_final,
            rpo_seconds  = rpo_final,
            schedules    = schedules,
            contacts     = contacts,
            procedures   = procedures,
            tabletop     = tabletop,
        )

    def _build_procedures(self, schedules: List[BackupSchedule]) -> List[dict]:
        """Generate standard restoration procedures for ML artefacts."""
        procs = [
            {
                "title":       "Declare DR Event and Notify Contacts",
                "description": "Open a war room, notify on-call contacts, and post in the DR Slack channel.",
                "commands":    [],
            },
            {
                "title":       "Assess Scope of Outage",
                "description": "Identify which resources are affected and their last known good state.",
                "commands":    [
                    "# List available backup recovery points",
                    "aws backup list-recovery-points-by-backup-vault --backup-vault-name ml-backup-vault",
                ],
            },
        ]
        for s in sorted(schedules, key=lambda x: x.tier):
            if s.resource_type == "s3_bucket":
                procs.append({
                    "title":       f"Restore {s.name} (Tier {s.tier})",
                    "description": f"Restore S3 bucket '{s.resource_id}' from backup vault.",
                    "commands":    [
                        f"# Identify latest recovery point for {s.resource_id}",
                        f"aws backup list-recovery-points-by-resource \\",
                        f"  --resource-arn arn:aws:s3:::{s.resource_id}",
                        f"",
                        f"# Start restore job",
                        f"aws backup start-restore-job \\",
                        f"  --recovery-point-arn <RECOVERY_POINT_ARN> \\",
                        f"  --metadata destinationBucketName={s.resource_id}-restored",
                    ],
                })
            elif s.resource_type == "dynamodb":
                procs.append({
                    "title":       f"Restore {s.name} (Tier {s.tier})",
                    "description": f"Restore DynamoDB table '{s.resource_id}' from backup.",
                    "commands":    [
                        f"aws dynamodb restore-table-from-backup \\",
                        f"  --target-table-name {s.resource_id}-restored \\",
                        f"  --backup-arn <BACKUP_ARN>",
                    ],
                })
        procs += [
            {
                "title":       "Verify Restoration Integrity",
                "description": "Run restoration_verifier.py against each restored artefact.",
                "commands":    [
                    "python restoration_verifier.py --path <restored_file> "
                    "--sha256 <expected_sha256> --size <expected_bytes>",
                ],
            },
            {
                "title":       "Run ML Pipeline Smoke Tests",
                "description": "Execute smoke tests to confirm the restored model loads and produces expected outputs.",
                "commands":    [
                    "pytest tests/smoke/ -v --timeout=120",
                ],
            },
            {
                "title":       "Update DNS / Traffic Routing",
                "description": "Redirect inference traffic to the recovered environment.",
                "commands":    [],
            },
            {
                "title":       "Document the Incident",
                "description": "Complete a post-mortem using the template in docs/postmortem-template.md.",
                "commands":    [],
            },
        ]
        return procs

    def _build_tabletop(self, schedules: List[BackupSchedule], platform: str) -> List[str]:
        return [
            f"Confirm all {len(schedules)} backup schedules are registered and enabled.",
            "Verify at least one successful backup job exists for each Tier 1 resource.",
            "Simulate S3 bucket deletion — can the team identify the last recovery point within 5 minutes?",
            "Simulate DynamoDB table loss — can metadata be restored within the Tier 3 RTO?",
            "Verify restoration certificates are generated and match expected checksums.",
            "Confirm all escalation contacts are reachable and on-call rotation is current.",
            "Test that the ML pipeline produces correct outputs after restoration (smoke tests pass).",
            "Measure actual RTO achieved during tabletop — compare against target.",
            "Update this runbook if any procedures failed or contacts have changed.",
            f"Schedule next tabletop exercise (recommended: quarterly for {platform}).",
        ]
