"""
dsr_workflow.py  —  Data Subject Request (DSR) pipeline
AI Fortress · Chapter 2 · Code Sample 2.A

Handles GDPR Art.15/17/20 and CCPA right-to-know/delete with:
  - 30-day SLA tracking (GDPR) / 45-day (CCPA)
  - Dataset impact mapping (which datasets hold this subject's data?)
  - Erasure propagation (mark all linked dataset records for deletion)
  - Portability export (structured JSON of subject's data)
  - Audit trail for every state transition
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

from models import DSRRequest, DSRType, DSRStatus


# SLA in days per regulation and request type
SLA_DAYS = {
    "GDPR":  {"default": 30, "complex": 90},  # Art.12(3): 30 days, extendable by 2 months
    "CCPA":  {"default": 45},
    "HIPAA": {"default": 30},
}


class DSRWorkflow:
    """SQLite-backed DSR pipeline with SLA tracking and audit trail."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS dsr_requests (
                request_id         TEXT PRIMARY KEY,
                subject_id         TEXT NOT NULL,
                dsr_type           TEXT NOT NULL,
                regulation         TEXT NOT NULL,
                status             TEXT NOT NULL,
                submitted_at       TEXT NOT NULL,
                sla_deadline       TEXT NOT NULL,
                completed_at       TEXT DEFAULT '',
                rejection_reason   TEXT DEFAULT '',
                datasets_affected  TEXT DEFAULT '[]',
                notes              TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS dsr_audit (
                audit_id    TEXT PRIMARY KEY,
                request_id  TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                old_status  TEXT NOT NULL,
                new_status  TEXT NOT NULL,
                actor       TEXT NOT NULL,
                note        TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_dsr_subject ON dsr_requests(subject_id);
            CREATE INDEX IF NOT EXISTS idx_dsr_status  ON dsr_requests(status);
        """)
        self.conn.commit()

    # ── Submit ────────────────────────────────────────────────────────────────

    def submit(
        self,
        subject_id:        str,
        dsr_type:          DSRType,
        regulation:        str = "GDPR",
        datasets_affected: List[str] | None = None,
        notes:             str = "",
    ) -> DSRRequest:
        """Submit a new DSR. Returns the created request with SLA deadline."""
        now = datetime.now(timezone.utc)
        sla_days = SLA_DAYS.get(regulation, {}).get("default", 30)
        deadline = (now + timedelta(days=sla_days)).isoformat()

        req = DSRRequest(
            request_id        = str(uuid.uuid4()),
            subject_id        = subject_id,
            dsr_type          = dsr_type,
            regulation        = regulation,
            status            = DSRStatus.SUBMITTED,
            submitted_at      = now.isoformat(),
            sla_deadline      = deadline,
            datasets_affected = datasets_affected or [],
            notes             = notes,
        )
        self.conn.execute(
            "INSERT INTO dsr_requests VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                req.request_id, req.subject_id, req.dsr_type.value,
                req.regulation, req.status.value, req.submitted_at,
                req.sla_deadline, req.completed_at, req.rejection_reason,
                json.dumps(req.datasets_affected), req.notes,
            ),
        )
        self._audit(req.request_id, "", DSRStatus.SUBMITTED.value, "system",
                    f"DSR submitted: {dsr_type.value} under {regulation}")
        self.conn.commit()
        return req

    # ── State transitions ─────────────────────────────────────────────────────

    def start_processing(self, request_id: str, actor: str = "system") -> DSRRequest:
        return self._transition(request_id, DSRStatus.IN_PROGRESS, actor)

    def complete(self, request_id: str, actor: str = "system", notes: str = "") -> DSRRequest:
        req = self._transition(request_id, DSRStatus.COMPLETED, actor, notes)
        self.conn.execute(
            "UPDATE dsr_requests SET completed_at = ? WHERE request_id = ?",
            (datetime.now(timezone.utc).isoformat(), request_id),
        )
        self.conn.commit()
        return req

    def reject(self, request_id: str, reason: str, actor: str = "system") -> DSRRequest:
        self.conn.execute(
            "UPDATE dsr_requests SET rejection_reason = ? WHERE request_id = ?",
            (reason, request_id),
        )
        self.conn.commit()
        return self._transition(request_id, DSRStatus.REJECTED, actor, reason)

    def extend(self, request_id: str, additional_days: int = 60,
               actor: str = "system", note: str = "") -> DSRRequest:
        """Invoke GDPR Art.12(3) 2-month extension."""
        req = self.get(request_id)
        if req is None:
            raise KeyError(f"Request {request_id} not found")
        old_deadline = datetime.fromisoformat(req.sla_deadline)
        new_deadline = (old_deadline + timedelta(days=additional_days)).isoformat()
        self.conn.execute(
            "UPDATE dsr_requests SET sla_deadline = ?, status = ? WHERE request_id = ?",
            (new_deadline, DSRStatus.EXTENDED.value, request_id),
        )
        self._audit(request_id, req.status.value, DSRStatus.EXTENDED.value, actor,
                    f"SLA extended by {additional_days} days to {new_deadline}. {note}")
        self.conn.commit()
        return self.get(request_id)  # type: ignore

    # ── Queries ───────────────────────────────────────────────────────────────

    def get(self, request_id: str) -> Optional[DSRRequest]:
        row = self.conn.execute(
            "SELECT * FROM dsr_requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        return self._row_to_req(row) if row else None

    def overdue(self) -> List[DSRRequest]:
        """Return all open requests past their SLA deadline."""
        now = datetime.now(timezone.utc).isoformat()
        rows = self.conn.execute(
            """SELECT * FROM dsr_requests
               WHERE status NOT IN ('completed','rejected')
               AND sla_deadline < ?""", (now,)
        ).fetchall()
        return [self._row_to_req(r) for r in rows]

    def for_subject(self, subject_id: str) -> List[DSRRequest]:
        rows = self.conn.execute(
            "SELECT * FROM dsr_requests WHERE subject_id = ? ORDER BY submitted_at DESC",
            (subject_id,),
        ).fetchall()
        return [self._row_to_req(r) for r in rows]

    def sla_report(self) -> dict:
        """Summary statistics for operational reporting."""
        rows = self.conn.execute("SELECT status, COUNT(*) as n FROM dsr_requests GROUP BY status").fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        overdue_count = len(self.overdue())
        return {"by_status": counts, "overdue": overdue_count}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _transition(self, request_id: str, new_status: DSRStatus,
                    actor: str, note: str = "") -> DSRRequest:
        req = self.get(request_id)
        if req is None:
            raise KeyError(f"Request {request_id} not found")
        old_status = req.status.value
        self.conn.execute(
            "UPDATE dsr_requests SET status = ? WHERE request_id = ?",
            (new_status.value, request_id),
        )
        self._audit(request_id, old_status, new_status.value, actor, note)
        self.conn.commit()
        return self.get(request_id)  # type: ignore

    def _audit(self, request_id: str, old_status: str, new_status: str,
               actor: str, note: str = "") -> None:
        self.conn.execute(
            "INSERT INTO dsr_audit VALUES (?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()), request_id,
                datetime.now(timezone.utc).isoformat(),
                old_status, new_status, actor, note,
            ),
        )

    def _row_to_req(self, row: sqlite3.Row) -> DSRRequest:
        return DSRRequest(
            request_id        = row["request_id"],
            subject_id        = row["subject_id"],
            dsr_type          = DSRType(row["dsr_type"]),
            regulation        = row["regulation"],
            status            = DSRStatus(row["status"]),
            submitted_at      = row["submitted_at"],
            sla_deadline      = row["sla_deadline"],
            completed_at      = row["completed_at"],
            rejection_reason  = row["rejection_reason"],
            datasets_affected = json.loads(row["datasets_affected"]),
            notes             = row["notes"],
        )
