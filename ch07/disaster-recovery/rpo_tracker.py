"""
rpo_tracker.py  —  RPO exposure monitoring and breach alerting
AI Fortress · Chapter 7 · Code Sample 7.C

Tracks Recovery Point Objective exposure for all protected ML resources and
produces a compliance report for DR audits.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from backup_scheduler import BackupScheduler, BackupSchedule, OverdueAlert


@dataclass
class RPOStatus:
    schedule_id:     str
    resource_id:     str
    resource_type:   str
    rpo_target_s:    int
    exposure_s:      int        # current exposure in seconds
    compliance:      str        # "COMPLIANT" | "WARNING" | "BREACH"
    last_backup_at:  Optional[str]
    rpo_utilisation: float      # exposure / rpo_target (1.0 = right at limit)


@dataclass
class RPOReport:
    generated_at:    str
    total_resources: int
    compliant:       int
    warning:         int
    breach:          int
    statuses:        List[RPOStatus]
    overall_pass:    bool       # True if no BREACH

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} RPO Compliance: {self.compliant}/{self.total_resources} compliant, "
            f"{self.warning} warning, {self.breach} breach."
        )


class RPOTracker:
    """
    Monitors RPO exposure across all registered backup schedules.

    Parameters
    ----------
    scheduler : BackupScheduler with registered schedules and job history
    """

    def __init__(self, scheduler: BackupScheduler):
        self.scheduler = scheduler

    def report(self, now: Optional[datetime] = None) -> RPOReport:
        """Generate a full RPO compliance report for all schedules."""
        if now is None:
            now = datetime.now(timezone.utc)

        statuses: List[RPOStatus] = []

        for schedule in self.scheduler.all_schedules():
            if not schedule.enabled:
                continue
            last = self.scheduler.last_successful_job(schedule.schedule_id)
            if last is None:
                exposure = int(365 * 24 * 3600)   # never backed up
                last_at  = None
            else:
                completed = datetime.fromisoformat(last.completed_at)
                if completed.tzinfo is None:
                    completed = completed.replace(tzinfo=timezone.utc)
                exposure = max(0, int((now - completed).total_seconds()))
                last_at  = last.completed_at

            rpo = schedule.rpo_seconds
            utilisation = exposure / rpo if rpo > 0 else float("inf")

            if utilisation <= 0.80:
                compliance = "COMPLIANT"
            elif utilisation <= 1.0:
                compliance = "WARNING"
            else:
                compliance = "BREACH"

            statuses.append(RPOStatus(
                schedule_id     = schedule.schedule_id,
                resource_id     = schedule.resource_id,
                resource_type   = schedule.resource_type,
                rpo_target_s    = rpo,
                exposure_s      = exposure,
                compliance      = compliance,
                last_backup_at  = last_at,
                rpo_utilisation = round(utilisation, 4),
            ))

        compliant = sum(1 for s in statuses if s.compliance == "COMPLIANT")
        warning   = sum(1 for s in statuses if s.compliance == "WARNING")
        breach    = sum(1 for s in statuses if s.compliance == "BREACH")

        return RPOReport(
            generated_at     = now.isoformat(),
            total_resources  = len(statuses),
            compliant        = compliant,
            warning          = warning,
            breach           = breach,
            statuses         = statuses,
            overall_pass     = breach == 0,
        )
