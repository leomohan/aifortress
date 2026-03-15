"""
backup_scheduler.py  —  ML artefact backup schedule definition and tracking
AI Fortress · Chapter 7 · Code Sample 7.C

Defines backup schedules for ML artefacts and tracks job execution history.
Raises alerts when backups are overdue relative to the RPO target.

Backup tiers for ML platforms:
  TIER_1 (model checkpoints)  : RPO ≤ 1 hour  — continuous or hourly
  TIER_2 (training datasets)  : RPO ≤ 4 hours — every 4 hours
  TIER_3 (experiment metadata): RPO ≤ 24 hours — daily
  TIER_4 (infra state)        : RPO ≤ 24 hours — daily
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class BackupSchedule:
    schedule_id:    str
    name:           str
    resource_id:    str           # bucket name, volume ID, DB identifier, etc.
    resource_type:  str           # "s3_bucket" | "ebs_volume" | "rds" | "dynamodb"
    tier:           int           # 1–4
    rpo_seconds:    int           # Recovery Point Objective in seconds
    description:    str
    destination:    str           # backup destination (bucket/vault ARN)
    enabled:        bool = True


@dataclass
class BackupJob:
    job_id:        str
    schedule_id:   str
    started_at:    str
    completed_at:  Optional[str]
    status:        str            # "running" | "success" | "failed"
    size_bytes:    int = 0
    checksum:      str = ""       # SHA-256 of backup artefact
    error_message: str = ""


@dataclass
class OverdueAlert:
    schedule_id:    str
    resource_id:    str
    rpo_seconds:    int
    exposure_seconds: int         # time since last successful backup
    last_backup_at:  Optional[str]
    severity:        str          # "WARNING" | "CRITICAL"


class BackupScheduler:
    """
    Manages backup schedules and tracks job history for ML artefacts.
    """

    def __init__(self):
        self._schedules: Dict[str, BackupSchedule] = {}
        self._jobs:      Dict[str, List[BackupJob]] = {}   # schedule_id → jobs

    # ── Schedule management ───────────────────────────────────────────────────

    def register(self, schedule: BackupSchedule) -> None:
        self._schedules[schedule.schedule_id] = schedule
        if schedule.schedule_id not in self._jobs:
            self._jobs[schedule.schedule_id] = []

    def register_from_dict(self, d: dict) -> BackupSchedule:
        s = BackupSchedule(**d)
        self.register(s)
        return s

    def get_schedule(self, schedule_id: str) -> Optional[BackupSchedule]:
        return self._schedules.get(schedule_id)

    def all_schedules(self) -> List[BackupSchedule]:
        return list(self._schedules.values())

    # ── Job tracking ──────────────────────────────────────────────────────────

    def record_job(self, job: BackupJob) -> None:
        if job.schedule_id not in self._jobs:
            self._jobs[job.schedule_id] = []
        self._jobs[job.schedule_id].append(job)

    def last_successful_job(self, schedule_id: str) -> Optional[BackupJob]:
        """Return the most recent successful BackupJob for a schedule."""
        jobs = [j for j in self._jobs.get(schedule_id, []) if j.status == "success"]
        if not jobs:
            return None
        return max(jobs, key=lambda j: j.completed_at or "")

    def job_history(self, schedule_id: str) -> List[BackupJob]:
        return list(self._jobs.get(schedule_id, []))

    # ── Overdue detection ─────────────────────────────────────────────────────

    def check_overdue(self, now: Optional[datetime] = None) -> List[OverdueAlert]:
        """
        Check all enabled schedules for overdue backups.
        Returns a list of OverdueAlert for any schedule whose RPO is breached.
        """
        if now is None:
            now = datetime.now(timezone.utc)
        alerts: List[OverdueAlert] = []

        for sid, schedule in self._schedules.items():
            if not schedule.enabled:
                continue
            last = self.last_successful_job(sid)
            if last is None:
                exposure = int(1e9)   # never backed up → infinite exposure
                last_at  = None
            else:
                completed = datetime.fromisoformat(last.completed_at)
                if completed.tzinfo is None:
                    completed = completed.replace(tzinfo=timezone.utc)
                exposure  = int((now - completed).total_seconds())
                last_at   = last.completed_at

            if exposure > schedule.rpo_seconds:
                severity = "CRITICAL" if exposure > schedule.rpo_seconds * 2 else "WARNING"
                alerts.append(OverdueAlert(
                    schedule_id      = sid,
                    resource_id      = schedule.resource_id,
                    rpo_seconds      = schedule.rpo_seconds,
                    exposure_seconds = exposure,
                    last_backup_at   = last_at,
                    severity         = severity,
                ))
        return alerts

    def save_state(self, path: str | Path) -> None:
        import dataclasses
        state = {
            "schedules": {sid: dataclasses.asdict(s) for sid, s in self._schedules.items()},
            "jobs":      {sid: [dataclasses.asdict(j) for j in jobs]
                          for sid, jobs in self._jobs.items()},
        }
        Path(path).write_text(json.dumps(state, indent=2), encoding="utf-8")

    @classmethod
    def load_state(cls, path: str | Path) -> "BackupScheduler":
        scheduler = cls()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for sid, sd in data.get("schedules", {}).items():
            scheduler._schedules[sid] = BackupSchedule(**sd)
        for sid, jobs in data.get("jobs", {}).items():
            scheduler._jobs[sid] = [BackupJob(**j) for j in jobs]
        return scheduler


# ── Convenience factory for standard ML backup schedules ─────────────────────

def standard_ml_schedules(
    checkpoint_bucket: str,
    dataset_bucket:    str,
    metadata_table:    str,
    backup_vault:      str,
) -> List[BackupSchedule]:
    """Return a standard set of backup schedules for an ML platform."""
    return [
        BackupSchedule(
            schedule_id   = "sched-checkpoints",
            name          = "Model checkpoint hourly backup",
            resource_id   = checkpoint_bucket,
            resource_type = "s3_bucket",
            tier          = 1,
            rpo_seconds   = 3600,
            description   = "Hourly backup of model checkpoints. RPO = 1h.",
            destination   = backup_vault,
        ),
        BackupSchedule(
            schedule_id   = "sched-datasets",
            name          = "Training dataset 4h backup",
            resource_id   = dataset_bucket,
            resource_type = "s3_bucket",
            tier          = 2,
            rpo_seconds   = 4 * 3600,
            description   = "4-hourly backup of training datasets. RPO = 4h.",
            destination   = backup_vault,
        ),
        BackupSchedule(
            schedule_id   = "sched-metadata",
            name          = "Experiment metadata daily backup",
            resource_id   = metadata_table,
            resource_type = "dynamodb",
            tier          = 3,
            rpo_seconds   = 24 * 3600,
            description   = "Daily DynamoDB backup of experiment metadata. RPO = 24h.",
            destination   = backup_vault,
        ),
    ]
