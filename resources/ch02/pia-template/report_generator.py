"""
report_generator.py  —  Compliance gap report output (JSON + Markdown)
AI Fortress · Chapter 2 · Code Sample 2.C
"""
from __future__ import annotations
import json
from pathlib import Path
from control_registry import ControlStatus
from gap_analyser import GapReport


class ReportGenerator:

    def to_json(self, report: GapReport, output_path: str | Path | None = None) -> str:
        data = {
            "dataset_id":   report.dataset_id,
            "generated_at": report.generated_at,
            "regulations":  report.regulations,
            "summary":      report.summary_counts(),
            "assessments": [
                {
                    "control_id":       a.control.control_id,
                    "regulation":       a.control.regulation,
                    "article":          a.control.article,
                    "title":            a.control.title,
                    "status":           a.status.value,
                    "evidence_met":     a.evidence_met,
                    "evidence_missing": a.evidence_missing,
                }
                for a in report.assessments
            ],
        }
        text = json.dumps(data, indent=2)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
        return text

    def to_markdown(self, report: GapReport, output_path: str | Path | None = None) -> str:
        counts = report.summary_counts()
        lines = [
            f"# Compliance Gap Report — {report.dataset_id}",
            f"**Generated:** {report.generated_at}  ",
            f"**Regulations:** {', '.join(report.regulations)}",
            "",
            "## Summary",
            f"| Status | Count |",
            f"|--------|-------|",
        ]
        for status, count in counts.items():
            lines.append(f"| {status.upper()} | {count} |")

        for status in [ControlStatus.GAP, ControlStatus.PARTIAL, ControlStatus.COMPLIANT]:
            group = report.by_status(status)
            if not group:
                continue
            lines += ["", f"## {status.value.upper()} Controls ({len(group)})", ""]
            for a in group:
                icon = {"compliant":"✅","partial":"⚠️","gap":"❌","not_applicable":"—"}.get(status.value,"")
                lines.append(f"### {icon} {a.control.control_id} — {a.control.title}")
                lines.append(f"**Regulation:** {a.control.regulation} {a.control.article}  ")
                lines.append(f"**Category:** {a.control.category.value}  ")
                if a.evidence_met:
                    lines.append(f"**Evidence met:** {', '.join(a.evidence_met)}  ")
                if a.evidence_missing:
                    lines.append(f"**Evidence missing:** {', '.join(a.evidence_missing)}  ")
                lines.append(f"*{a.control.description}*")
                lines.append("")

        text = "\n".join(lines)
        if output_path:
            Path(output_path).write_text(text, encoding="utf-8")
        return text
