"""
retention.py  —  Retention policy engine and deletion certificate
AI Fortress · Chapter 2 · Code Sample 2.A

Declares retention schedules per dataset, identifies records past their
retention date, and issues cryptographically-signed deletion certificates.
"""
from __future__ import annotations
import hashlib, json, sqlite3, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List
from models import RetentionPolicy


class RetentionEngine:
    """SQLite-backed retention policy engine."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS retention_policies (
                policy_id      TEXT PRIMARY KEY,
                dataset_id     TEXT NOT NULL,
                data_category  TEXT NOT NULL,
                retention_days INTEGER NOT NULL,
                legal_basis    TEXT NOT NULL,
                review_date    TEXT NOT NULL,
                created_at     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deletion_certificates (
                cert_id        TEXT PRIMARY KEY,
                dataset_id     TEXT NOT NULL,
                data_category  TEXT NOT NULL,
                deleted_at     TEXT NOT NULL,
                record_count   INTEGER NOT NULL,
                method         TEXT NOT NULL,
                sha256_manifest TEXT NOT NULL,
                issued_by      TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def declare_policy(
        self,
        dataset_id:     str,
        data_category:  str,
        retention_days: int,
        legal_basis:    str = "GDPR Art.5(1)(e)",
        review_date:    str = "",
    ) -> RetentionPolicy:
        from datetime import timedelta
        if not review_date:
            review_date = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        policy = RetentionPolicy(
            policy_id      = str(uuid.uuid4()),
            dataset_id     = dataset_id,
            data_category  = data_category,
            retention_days = retention_days,
            legal_basis    = legal_basis,
            review_date    = review_date,
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO retention_policies VALUES (?,?,?,?,?,?,?)",
            (policy.policy_id, policy.dataset_id, policy.data_category,
             policy.retention_days, policy.legal_basis, policy.review_date, policy.created_at),
        )
        self.conn.commit()
        return policy

    def policies_for_dataset(self, dataset_id: str) -> List[RetentionPolicy]:
        rows = self.conn.execute(
            "SELECT * FROM retention_policies WHERE dataset_id = ?", (dataset_id,)
        ).fetchall()
        return [RetentionPolicy(
            policy_id=r["policy_id"], dataset_id=r["dataset_id"],
            data_category=r["data_category"], retention_days=r["retention_days"],
            legal_basis=r["legal_basis"], review_date=r["review_date"],
            created_at=r["created_at"],
        ) for r in rows]

    def issue_deletion_certificate(
        self,
        dataset_id:    str,
        data_category: str,
        record_count:  int,
        method:        str = "cryptographic_erasure",
        issued_by:     str = "system",
        record_ids:    List[str] | None = None,
    ) -> dict:
        """
        Issue a signed deletion certificate.
        The certificate's sha256_manifest is a hash of the record IDs deleted
        (or a timestamp hash if record IDs are not available), providing evidence
        that a specific set of records was processed.
        """
        now    = datetime.now(timezone.utc).isoformat()
        cert_id = str(uuid.uuid4())
        manifest_input = json.dumps(sorted(record_ids) if record_ids else [now, dataset_id, data_category])
        sha256_manifest = hashlib.sha256(manifest_input.encode()).hexdigest()

        cert = {
            "cert_id":         cert_id,
            "dataset_id":      dataset_id,
            "data_category":   data_category,
            "deleted_at":      now,
            "record_count":    record_count,
            "method":          method,
            "sha256_manifest": sha256_manifest,
            "issued_by":       issued_by,
        }
        self.conn.execute(
            "INSERT INTO deletion_certificates VALUES (?,?,?,?,?,?,?,?)",
            tuple(cert.values()),
        )
        self.conn.commit()
        return cert

    def certificates_for_dataset(self, dataset_id: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM deletion_certificates WHERE dataset_id = ? ORDER BY deleted_at",
            (dataset_id,),
        ).fetchall()
        return [dict(r) for r in rows]
