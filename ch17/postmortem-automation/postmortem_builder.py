"""
postmortem_builder.py  —  Postmortem report builder
AI Fortress · Chapter 17 · Code Sample 17.C

Assembles a complete, blameless AI security incident postmortem
from timeline, findings, and action items.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from finding_extractor import FindingsSummary
from action_tracker import ActionItem


@dataclass
class PostmortemReport:
    report_id:         str
    incident_id:       str
    title:             str
    severity:          str
    summary:           str
    timeline_summary:  str
    findings:          FindingsSummary
    actions:           List[ActionItem]
    lessons_learned:   List[str]
    generated_at:      str
    authors:           List[str]

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def save_markdown(self, path: str | Path) -> None:
        md = self._to_markdown()
        Path(path).write_text(md, encoding="utf-8")

    def _to_markdown(self) -> str:
        actions_md = "\n".join(
            f"| {a.action_id} | {a.title} | {a.owner} | {a.due_date} | {a.status} |"
            for a in self.actions
        )
        root_causes = "\n".join(
            f"- **[{f.category}]** {f.title}: {f.description}"
            for f in self.findings.root_causes
        ) or "_None identified_"
        lessons = "\n".join(f"- {l}" for l in self.lessons_learned) or "_None yet_"

        return f"""# Postmortem: {self.title}

**Incident ID:** {self.incident_id}  
**Severity:** {self.severity}  
**Generated:** {self.generated_at}  
**Authors:** {', '.join(self.authors)}

---

## Summary

{self.summary}

## Timeline Summary

{self.timeline_summary}

## Root Causes

{root_causes}

## All Findings

| ID | Category | Title | Phase | Severity | Root Cause |
|----|----------|-------|-------|----------|-----------|
""" + "\n".join(
    f"| {f.finding_id} | {f.category} | {f.title} | {f.phase} | {f.severity} | {'✓' if f.root_cause else ''} |"
    for f in self.findings.findings
) + f"""

## Action Items

| ID | Title | Owner | Due Date | Status |
|----|-------|-------|---------|--------|
{actions_md if actions_md else "_No actions yet_"}

## Lessons Learned

{lessons}

---
*Blameless postmortem — AI Fortress Chapter 17*
"""


class PostmortemBuilder:
    """Assembles a postmortem report from IR artefacts."""

    def build(
        self,
        incident_id:       str,
        title:             str,
        severity:          str,
        summary:           str,
        timeline_summary:  str,
        findings:          FindingsSummary,
        actions:           List[ActionItem],
        lessons_learned:   List[str],
        authors:           List[str],
    ) -> PostmortemReport:
        return PostmortemReport(
            report_id        = str(uuid.uuid4())[:8],
            incident_id      = incident_id,
            title            = title,
            severity         = severity,
            summary          = summary,
            timeline_summary = timeline_summary,
            findings         = findings,
            actions          = actions,
            lessons_learned  = lessons_learned,
            generated_at     = datetime.now(timezone.utc).isoformat(),
            authors          = authors,
        )
