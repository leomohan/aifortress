"""
lawful_basis.py  —  Lawful-basis registry and consent tracker
AI Fortress · Chapter 2 · Code Sample 2.A

Maintains a SQLite-backed registry of:
  - DatasetRecord: the legal basis for each dataset's processing
  - ConsentRecord: individual consent grants and withdrawals per data subject
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

from models import DatasetRecord, ConsentRecord, LegalBasis


class LawfulBasisRegistry:
    """
    SQLite-backed registry of dataset lawful bases and consent records.

    In production, replace SQLite with your governance database (PostgreSQL,
    DynamoDB, etc.).  The interface remains identical.
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS datasets (
                dataset_id       TEXT PRIMARY KEY,
                name             TEXT NOT NULL,
                legal_basis      TEXT NOT NULL,
                purpose          TEXT NOT NULL,
                data_categories  TEXT NOT NULL,   -- JSON array
                special_categories TEXT NOT NULL, -- JSON array
                controller       TEXT NOT NULL,
                processor        TEXT NOT NULL,
                retention_days   INTEGER NOT NULL,
                registered_at    TEXT NOT NULL,
                notes            TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS consent_records (
                consent_id   TEXT PRIMARY KEY,
                subject_id   TEXT NOT NULL,
                dataset_id   TEXT NOT NULL,
                purpose      TEXT NOT NULL,
                granted_at   TEXT NOT NULL,
                expires_at   TEXT DEFAULT '',
                withdrawn_at TEXT DEFAULT '',
                evidence_ref TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_consent_subject ON consent_records(subject_id);
            CREATE INDEX IF NOT EXISTS idx_consent_dataset  ON consent_records(dataset_id);
        """)
        self.conn.commit()

    # ── Dataset registration ──────────────────────────────────────────────────

    def register(
        self,
        dataset_id:        str,
        legal_basis:       LegalBasis,
        purpose:           str,
        data_categories:   List[str],
        retention_days:    int,
        name:              str = "",
        special_categories: List[str] | None = None,
        controller:        str = "",
        processor:         str = "",
        notes:             str = "",
    ) -> DatasetRecord:
        """Register a dataset's lawful basis for processing."""
        record = DatasetRecord(
            dataset_id        = dataset_id,
            name              = name or dataset_id,
            legal_basis       = legal_basis,
            purpose           = purpose,
            data_categories   = data_categories,
            special_categories = special_categories or [],
            controller        = controller,
            processor         = processor,
            retention_days    = retention_days,
            notes             = notes,
        )
        self.conn.execute(
            """INSERT OR REPLACE INTO datasets VALUES
               (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                record.dataset_id, record.name, record.legal_basis.value,
                record.purpose,
                json.dumps(record.data_categories),
                json.dumps(record.special_categories),
                record.controller, record.processor,
                record.retention_days, record.registered_at, record.notes,
            ),
        )
        self.conn.commit()
        return record

    def get_dataset(self, dataset_id: str) -> Optional[DatasetRecord]:
        row = self.conn.execute(
            "SELECT * FROM datasets WHERE dataset_id = ?", (dataset_id,)
        ).fetchone()
        if not row:
            return None
        return DatasetRecord(
            dataset_id        = row["dataset_id"],
            name              = row["name"],
            legal_basis       = LegalBasis(row["legal_basis"]),
            purpose           = row["purpose"],
            data_categories   = json.loads(row["data_categories"]),
            special_categories = json.loads(row["special_categories"]),
            controller        = row["controller"],
            processor         = row["processor"],
            retention_days    = row["retention_days"],
            registered_at     = row["registered_at"],
            notes             = row["notes"],
        )

    def all_datasets(self) -> List[DatasetRecord]:
        rows = self.conn.execute("SELECT * FROM datasets ORDER BY registered_at").fetchall()
        return [self.get_dataset(r["dataset_id"]) for r in rows]  # type: ignore

    # ── Consent management ────────────────────────────────────────────────────

    def record_consent(
        self,
        subject_id:   str,
        dataset_id:   str,
        purpose:      str,
        expires_days: int = 0,   # 0 = no expiry
        evidence_ref: str = "",
    ) -> ConsentRecord:
        """Record a consent grant for a data subject."""
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=expires_days)).isoformat() if expires_days else ""
        record = ConsentRecord(
            consent_id   = str(uuid.uuid4()),
            subject_id   = subject_id,
            dataset_id   = dataset_id,
            purpose      = purpose,
            granted_at   = now.isoformat(),
            expires_at   = expires_at,
            evidence_ref = evidence_ref,
        )
        self.conn.execute(
            "INSERT INTO consent_records VALUES (?,?,?,?,?,?,?,?)",
            (record.consent_id, record.subject_id, record.dataset_id, record.purpose,
             record.granted_at, record.expires_at, record.withdrawn_at, record.evidence_ref),
        )
        self.conn.commit()
        return record

    def withdraw_consent(self, subject_id: str, dataset_id: str, purpose: str = "") -> int:
        """
        Mark all matching consent records as withdrawn.
        Returns number of records updated.
        """
        now = datetime.now(timezone.utc).isoformat()
        if purpose:
            cur = self.conn.execute(
                """UPDATE consent_records SET withdrawn_at = ?
                   WHERE subject_id = ? AND dataset_id = ? AND purpose = ?
                   AND withdrawn_at = ''""",
                (now, subject_id, dataset_id, purpose),
            )
        else:
            cur = self.conn.execute(
                """UPDATE consent_records SET withdrawn_at = ?
                   WHERE subject_id = ? AND dataset_id = ? AND withdrawn_at = ''""",
                (now, subject_id, dataset_id),
            )
        self.conn.commit()
        return cur.rowcount

    def active_consents_for_subject(self, subject_id: str) -> List[ConsentRecord]:
        """Return all active (not withdrawn, not expired) consents for a subject."""
        rows = self.conn.execute(
            "SELECT * FROM consent_records WHERE subject_id = ? AND withdrawn_at = ''",
            (subject_id,),
        ).fetchall()
        records = [
            ConsentRecord(
                consent_id   = r["consent_id"],
                subject_id   = r["subject_id"],
                dataset_id   = r["dataset_id"],
                purpose      = r["purpose"],
                granted_at   = r["granted_at"],
                expires_at   = r["expires_at"],
                withdrawn_at = r["withdrawn_at"],
                evidence_ref = r["evidence_ref"],
            )
            for r in rows
        ]
        return [c for c in records if c.is_active]

    def datasets_requiring_consent(self) -> List[DatasetRecord]:
        """Return all datasets whose lawful basis is CONSENT."""
        return [
            d for d in self.all_datasets()
            if d.legal_basis == LegalBasis.CONSENT
        ]

    def consent_coverage_report(self, dataset_id: str) -> dict:
        """Return consent statistics for a dataset."""
        total   = self.conn.execute(
            "SELECT COUNT(*) FROM consent_records WHERE dataset_id = ?", (dataset_id,)
        ).fetchone()[0]
        active  = self.conn.execute(
            "SELECT COUNT(*) FROM consent_records WHERE dataset_id = ? AND withdrawn_at = ''",
            (dataset_id,),
        ).fetchone()[0]
        withdrawn = total - active
        return {"dataset_id": dataset_id, "total": total, "active": active, "withdrawn": withdrawn}
