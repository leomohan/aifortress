"""
anonymisation_report.py  —  Audit report for anonymisation operations
AI Fortress · Chapter 2 · Code Sample 2.B
"""
from __future__ import annotations
import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from k_anonymity import AnonymisationResult


@dataclass
class AnonymisationReport:
    dataset_id:        str
    generated_at:      str
    original_rows:     int
    anonymised_rows:   int
    techniques_applied: List[str]
    pii_types_found:   Dict[str, int]   # pii_type → count
    k_anonymity:       Optional[dict]   # k-anon result dict or None
    l_diversity:       Optional[dict]
    pseudonymised_columns: List[str]
    suppression_rate:  float
    notes:             str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def summary(self) -> str:
        lines = [
            f"Anonymisation Report — {self.dataset_id}",
            f"  Generated at       : {self.generated_at}",
            f"  Original rows      : {self.original_rows}",
            f"  Anonymised rows    : {self.anonymised_rows}",
            f"  Suppression rate   : {self.suppression_rate:.1%}",
            f"  Techniques applied : {', '.join(self.techniques_applied)}",
        ]
        if self.pii_types_found:
            lines.append("  PII types detected :")
            for pt, cnt in sorted(self.pii_types_found.items()):
                lines.append(f"    {pt:<22} {cnt:>5}")
        if self.k_anonymity:
            lines.append(f"  k achieved         : {self.k_anonymity.get('k_achieved')}")
        if self.l_diversity:
            lines.append(f"  l achieved         : {self.l_diversity.get('l_achieved')}")
        return "\n".join(lines)


def build_report(
    dataset_id:            str,
    original_rows:         int,
    anonymised_rows:       int,
    techniques_applied:    List[str],
    pii_types_found:       Dict[str, int] | None = None,
    k_result:              AnonymisationResult | None = None,
    pseudonymised_columns: List[str] | None = None,
    notes:                 str = "",
) -> AnonymisationReport:
    suppression = (original_rows - anonymised_rows) / original_rows if original_rows else 0.0
    k_dict = None
    l_dict = None
    if k_result:
        k_dict = {"k_achieved": k_result.k_achieved, "equivalence_classes": k_result.equivalence_classes}
        if k_result.l_achieved is not None:
            l_dict = {"l_achieved": k_result.l_achieved}

    return AnonymisationReport(
        dataset_id             = dataset_id,
        generated_at           = datetime.now(timezone.utc).isoformat(),
        original_rows          = original_rows,
        anonymised_rows        = anonymised_rows,
        techniques_applied     = techniques_applied,
        pii_types_found        = pii_types_found or {},
        k_anonymity            = k_dict,
        l_diversity            = l_dict,
        pseudonymised_columns  = pseudonymised_columns or [],
        suppression_rate       = suppression,
        notes                  = notes,
    )
