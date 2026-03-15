"""
contamination_report.py  —  Unified contamination report aggregator
AI Fortress · Chapter 3 · Code Sample 3.A
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Union

Finding = Any   # union of all finding types


@dataclass
class ContaminationReport:
    dataset_id:   str
    generated_at: str = ""
    findings:     List[dict] = field(default_factory=list)

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def add_findings(self, findings: List[Finding]) -> None:
        for f in findings:
            self.findings.append(asdict(f) if hasattr(f, "__dataclass_fields__") else f)

    def critical(self) -> List[dict]:
        return [f for f in self.findings if f.get("severity") == "critical"]

    def warnings(self) -> List[dict]:
        return [f for f in self.findings if f.get("severity") == "warning"]

    def save(self, path: str | Path) -> None:
        data = {
            "dataset_id":   self.dataset_id,
            "generated_at": self.generated_at,
            "summary": {
                "critical": len(self.critical()),
                "warning":  len(self.warnings()),
                "info":     len([f for f in self.findings if f.get("severity") == "info"]),
            },
            "findings": self.findings,
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def summary(self) -> str:
        c = len(self.critical())
        w = len(self.warnings())
        lines = [
            f"Contamination Report — {self.dataset_id}",
            f"  Generated : {self.generated_at}",
            f"  Critical  : {c}",
            f"  Warnings  : {w}",
            f"  Total     : {len(self.findings)}",
        ]
        if c > 0:
            lines.append("\nCRITICAL findings:")
            for f in self.critical():
                lines.append(f"  [{f['detector']}] {f['description']}")
        return "\n".join(lines)
