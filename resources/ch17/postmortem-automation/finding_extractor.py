"""
finding_extractor.py  —  Postmortem finding extractor
AI Fortress · Chapter 17 · Code Sample 17.C

Extracts structured findings from incident timeline and evidence.
Categorises findings as: contributing_factor | missed_detection |
  process_gap | tool_gap | human_factor | communication_gap
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class Finding:
    finding_id:   str
    category:     str    # contributing_factor|missed_detection|process_gap|tool_gap|human_factor|communication_gap
    title:        str
    description:  str
    phase:        str    # when in incident lifecycle: detection|containment|eradication|recovery|preparation
    severity:     str    # "critical"|"high"|"moderate"|"low"
    root_cause:   bool   # True if this is identified as a root cause


@dataclass
class FindingsSummary:
    incident_id:       str
    findings:          List[Finding]
    root_causes:       List[Finding]
    n_critical:        int
    categories:        List[str]


class FindingExtractor:
    """Manages findings for an incident postmortem."""

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self._findings:  List[Finding] = []

    def add(
        self,
        category:    str,
        title:       str,
        description: str,
        phase:       str,
        severity:    str = "moderate",
        root_cause:  bool = False,
    ) -> Finding:
        f = Finding(
            finding_id  = str(uuid.uuid4())[:8],
            category    = category,
            title       = title,
            description = description,
            phase       = phase,
            severity    = severity,
            root_cause  = root_cause,
        )
        self._findings.append(f)
        return f

    def summarise(self) -> FindingsSummary:
        root_causes = [f for f in self._findings if f.root_cause]
        n_critical  = sum(1 for f in self._findings if f.severity == "critical")
        categories  = list(dict.fromkeys(f.category for f in self._findings))
        return FindingsSummary(
            incident_id = self.incident_id,
            findings    = list(self._findings),
            root_causes = root_causes,
            n_critical  = n_critical,
            categories  = categories,
        )
