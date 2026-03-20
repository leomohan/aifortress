"""
ropa.py  —  GDPR Article 30 Records of Processing Activities (RoPA)
AI Fortress · Chapter 2 · Code Sample 2.A
"""
from __future__ import annotations
import csv, json
from datetime import datetime, timezone
from pathlib import Path
from lawful_basis import LawfulBasisRegistry


class RoPAGenerator:
    """Generates GDPR Art.30 RoPA from the lawful-basis registry."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self.registry = LawfulBasisRegistry(db_path) if isinstance(db_path, (str, Path)) else db_path

    def as_records(self) -> list[dict]:
        datasets = self.registry.all_datasets()
        return [
            {
                "dataset_id":          d.dataset_id,
                "name":                d.name,
                "controller":          d.controller,
                "processor":           d.processor,
                "purpose":             d.purpose,
                "legal_basis":         d.legal_basis.value,
                "data_categories":     ", ".join(d.data_categories),
                "special_categories":  ", ".join(d.special_categories),
                "retention_days":      d.retention_days,
                "registered_at":       d.registered_at,
                "notes":               d.notes,
            }
            for d in datasets
        ]

    def export_csv(self, output_path: str | Path) -> None:
        records = self.as_records()
        if not records:
            return
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)

    def export_json(self, output_path: str | Path) -> None:
        Path(output_path).write_text(
            json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
                        "records": self.as_records()}, indent=2),
            encoding="utf-8",
        )
