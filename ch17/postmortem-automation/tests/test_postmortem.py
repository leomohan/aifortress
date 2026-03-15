"""
tests/test_postmortem.py
AI Fortress · Chapter 17 · Code Sample 17.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from datetime import datetime, timedelta, timezone
from finding_extractor import FindingExtractor
from action_tracker import ActionTracker
from postmortem_builder import PostmortemBuilder


# ── FindingExtractor ──────────────────────────────────────────────────────────

class TestFindingExtractor:

    def test_add_finding(self):
        fe = FindingExtractor("INC-001")
        f  = fe.add("process_gap", "No playbook", "Playbook was missing", "preparation", "high")
        assert f.finding_id
        assert f.category == "process_gap"

    def test_summarise(self):
        fe = FindingExtractor("INC-001")
        fe.add("process_gap",     "A", "desc", "preparation", "high")
        fe.add("tool_gap",        "B", "desc", "detection",   "moderate")
        fe.add("human_factor",    "C", "desc", "containment", "critical", root_cause=True)
        s  = fe.summarise()
        assert len(s.findings) == 3
        assert len(s.root_causes) == 1

    def test_n_critical_count(self):
        fe = FindingExtractor("INC-001")
        fe.add("process_gap", "A", "d", "preparation", "critical")
        fe.add("tool_gap",    "B", "d", "detection",   "moderate")
        s  = fe.summarise()
        assert s.n_critical == 1

    def test_categories_deduplicated(self):
        fe = FindingExtractor("INC-001")
        fe.add("process_gap", "A", "d", "p")
        fe.add("process_gap", "B", "d", "p")
        fe.add("tool_gap",    "C", "d", "p")
        s  = fe.summarise()
        assert s.categories.count("process_gap") == 1

    def test_root_causes_subset_of_findings(self):
        fe = FindingExtractor("INC-001")
        fe.add("tool_gap", "A", "d", "p", root_cause=True)
        fe.add("tool_gap", "B", "d", "p", root_cause=False)
        s  = fe.summarise()
        assert all(f.root_cause for f in s.root_causes)


# ── ActionTracker ─────────────────────────────────────────────────────────────

class TestActionTracker:

    def _due(self, days=30):
        return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    def test_add_action(self):
        at   = ActionTracker("INC-001")
        item = at.add("Deploy SBOM scanning", "desc", "ml-ops", self._due(), "P1")
        assert item.action_id
        assert item.status == "open"

    def test_update_status(self):
        at   = ActionTracker("INC-001")
        item = at.add("Task", "desc", "owner", self._due())
        at.update_status(item.action_id, "done")
        assert item.status == "done"
        assert item.closed_at is not None

    def test_open_items_filtered(self):
        at = ActionTracker("INC-001")
        a1 = at.add("Task A", "d", "o", self._due())
        a2 = at.add("Task B", "d", "o", self._due())
        at.update_status(a2.action_id, "done")
        assert len(at.open_items()) == 1

    def test_overdue_detection(self):
        at      = ActionTracker("INC-001")
        overdue = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        at.add("Overdue task", "d", "o", overdue)
        assert len(at.overdue_items()) == 1

    def test_update_unknown_raises(self):
        at = ActionTracker("INC-001")
        with pytest.raises(KeyError):
            at.update_status("ghost", "done")

    def test_persist(self, tmp_path):
        p  = tmp_path / "actions.json"
        at = ActionTracker("INC-001", storage_path=p)
        at.add("Task", "d", "o", self._due())
        data = json.loads(p.read_text())
        assert len(data) == 1

    def test_finding_id_linked(self):
        at   = ActionTracker("INC-001")
        item = at.add("Task", "d", "o", self._due(), finding_id="abc12345")
        assert item.finding_id == "abc12345"


# ── PostmortemBuilder ─────────────────────────────────────────────────────────

class TestPostmortemBuilder:

    def _build(self):
        fe = FindingExtractor("INC-001")
        fe.add("process_gap", "No playbook", "Missing playbook", "preparation", "high", True)
        at = ActionTracker("INC-001")
        due = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
        at.add("Create playbook", "Write and test playbook", "ir-lead", due, "P1")
        builder = PostmortemBuilder()
        return builder.build(
            incident_id      = "INC-001",
            title            = "Model extraction via unauth API",
            severity         = "P2",
            summary          = "Attacker extracted partial model weights via unauthenticated endpoint.",
            timeline_summary = "Detected T+4h; contained T+6h; recovered T+48h.",
            findings         = fe.summarise(),
            actions          = at.items(),
            lessons_learned  = ["Rate limit inference API", "Add model extraction detection"],
            authors          = ["alice@corp.com", "bob@corp.com"],
        )

    def test_build_report(self):
        report = self._build()
        assert report.report_id
        assert report.incident_id == "INC-001"

    def test_save_json(self, tmp_path):
        report = self._build()
        p      = tmp_path / "postmortem.json"
        report.save_json(p)
        data   = json.loads(p.read_text())
        assert "findings" in data

    def test_save_markdown(self, tmp_path):
        report = self._build()
        p      = tmp_path / "postmortem.md"
        report.save_markdown(p)
        text   = p.read_text()
        assert "# Postmortem:" in text
        assert "Root Causes" in text
        assert "Action Items" in text

    def test_unique_report_ids(self):
        builder = PostmortemBuilder()
        fe      = FindingExtractor("INC-001")
        s       = fe.summarise()
        r1 = builder.build("I","T","P2","s","tl",s,[]  ,[]  ,[])
        r2 = builder.build("I","T","P2","s","tl",s,[]  ,[]  ,[])
        assert r1.report_id != r2.report_id

    def test_lessons_learned_stored(self):
        report = self._build()
        assert len(report.lessons_learned) == 2
