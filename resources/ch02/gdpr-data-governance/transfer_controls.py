"""
transfer_controls.py  —  Cross-border transfer controls and HIPAA BAA registry
AI Fortress · Chapter 2 · Code Sample 2.A

Tracks GDPR Chapter V transfer mechanisms (SCCs, BCRs, adequacy decisions)
and HIPAA Business Associate Agreements for each data processor / vendor.
"""
from __future__ import annotations
import json, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from models import TransferMechanism


class TransferControlRegistry:
    def __init__(self, db_path: str | Path = ":memory:"):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS transfer_records (
                transfer_id      TEXT PRIMARY KEY,
                vendor_name      TEXT NOT NULL,
                destination_country TEXT NOT NULL,
                mechanism        TEXT NOT NULL,
                document_ref     TEXT NOT NULL,
                effective_date   TEXT NOT NULL,
                expiry_date      TEXT DEFAULT '',
                datasets         TEXT DEFAULT '[]',
                notes            TEXT DEFAULT '',
                registered_at    TEXT NOT NULL
            );
        """)
        self.conn.commit()

    def register_transfer(
        self,
        vendor_name:          str,
        destination_country:  str,
        mechanism:            TransferMechanism,
        document_ref:         str,
        effective_date:       str,
        expiry_date:          str = "",
        datasets:             List[str] | None = None,
        notes:                str = "",
    ) -> dict:
        record = {
            "transfer_id":          str(uuid.uuid4()),
            "vendor_name":          vendor_name,
            "destination_country":  destination_country,
            "mechanism":            mechanism.value,
            "document_ref":         document_ref,
            "effective_date":       effective_date,
            "expiry_date":          expiry_date,
            "datasets":             json.dumps(datasets or []),
            "notes":                notes,
            "registered_at":        datetime.now(timezone.utc).isoformat(),
        }
        self.conn.execute(
            "INSERT INTO transfer_records VALUES (?,?,?,?,?,?,?,?,?,?)",
            tuple(record.values()),
        )
        self.conn.commit()
        return record

    def transfers_for_vendor(self, vendor_name: str) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM transfer_records WHERE vendor_name = ?", (vendor_name,)
        ).fetchall()
        return [dict(r) for r in rows]

    def expiring_soon(self, days: int = 90) -> List[dict]:
        """Return transfers whose documents expire within the next N days."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
        rows   = self.conn.execute(
            "SELECT * FROM transfer_records WHERE expiry_date != '' AND expiry_date < ?",
            (cutoff,),
        ).fetchall()
        return [dict(r) for r in rows]

    def all_transfers(self) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM transfer_records ORDER BY vendor_name"
        ).fetchall()
        return [dict(r) for r in rows]
