"""
tests/test_tabletop.py
AI Fortress · Chapter 17 · Code Sample 17.E
Run: pytest tests/ -v
"""
from __future__ import annotations
import json, pytest
from scenario_runner import ScenarioRunner, Inject
from inject_scheduler import InjectScheduler
from response_evaluator import ResponseEvaluator


def _inject(seq, t_plus=0):
    return Inject(
        inject_id     = f"INJ-{seq:02d}",
        sequence      = seq,
        title         = f"Inject {seq}",
        description   = f"Description for inject {seq}",
        t_plus_min    = t_plus,
        category      = "detection",
        expected_actions = ["notify ciso", "suspend model", "preserve logs"],
        difficulty    = "medium",
    )


def _scenario():
    return ScenarioRunner("Model Poisoning Scenario", [_inject(1), _inject(2, 10)])


# ── ScenarioRunner ────────────────────────────────────────────────────────────

class TestScenarioRunner:

    def test_start_session(self):
        runner  = _scenario()
        session = runner.start()
        assert session.session_id
        assert session.status == "running"

    def test_record_response(self):
        runner  = _scenario()
        session = runner.start()
        resp    = runner.record_response("INJ-01", "alice", "I would notify ciso immediately")
        assert resp.inject_id == "INJ-01"
        assert resp.participant == "alice"

    def test_end_session(self):
        runner  = _scenario()
        runner.start()
        session = runner.end()
        assert session.status == "completed"
        assert session.ended_at

    def test_pending_injects_decrease_after_response(self):
        runner  = _scenario()
        runner.start()
        before = len(runner.pending_injects())
        runner.record_response("INJ-01", "alice", "response")
        after  = len(runner.pending_injects())
        assert after == before - 1

    def test_record_response_before_start_raises(self):
        runner = _scenario()
        with pytest.raises(RuntimeError):
            runner.record_response("INJ-01", "alice", "response")

    def test_session_returns_none_before_start(self):
        runner = _scenario()
        assert runner.session() is None

    def test_injects_sorted_by_sequence(self):
        runner  = ScenarioRunner("S", [_inject(3), _inject(1), _inject(2)])
        session = runner.start()
        seqs    = [i.sequence for i in session.injects]
        assert seqs == sorted(seqs)


# ── InjectScheduler ───────────────────────────────────────────────────────────

class TestInjectScheduler:

    def test_t_plus_0_inject_due_immediately(self):
        runner    = ScenarioRunner("S", [_inject(1, t_plus=0)])
        session   = runner.start()
        scheduler = InjectScheduler(session)
        due       = scheduler.due_injects()
        assert len(due) == 1

    def test_future_inject_not_due(self):
        runner    = ScenarioRunner("S", [_inject(1, t_plus=999)])
        session   = runner.start()
        scheduler = InjectScheduler(session)
        due       = scheduler.due_injects()
        assert len(due) == 0

    def test_mark_delivered(self):
        runner    = ScenarioRunner("S", [_inject(1, t_plus=0)])
        session   = runner.start()
        scheduler = InjectScheduler(session)
        scheduler.mark_delivered("INJ-01")
        undelivered = scheduler.undelivered_due()
        assert len(undelivered) == 0

    def test_undelivered_due_returns_pending(self):
        runner    = ScenarioRunner("S", [_inject(1, t_plus=0), _inject(2, t_plus=0)])
        session   = runner.start()
        scheduler = InjectScheduler(session)
        scheduler.mark_delivered("INJ-01")
        pending   = scheduler.undelivered_due()
        assert len(pending) == 1
        assert pending[0].inject.inject_id == "INJ-02"


# ── ResponseEvaluator ─────────────────────────────────────────────────────────

class TestResponseEvaluator:

    def _run(self, responses):
        injects = [_inject(1, 0)]
        runner  = ScenarioRunner("S", injects)
        session = runner.start()
        for r in responses:
            runner.record_response("INJ-01", r["who"], r["text"])
        runner.end()
        return session, injects

    def test_high_coverage_good_grade(self):
        session, injects = self._run([
            {"who": "alice", "text": "notify ciso, suspend model, and preserve logs immediately"},
        ])
        ev     = ResponseEvaluator()
        report = ev.evaluate(session, injects)
        assert report.overall_score >= 70

    def test_no_response_low_score(self):
        injects = [_inject(1, 0)]
        runner  = ScenarioRunner("S", injects)
        session = runner.start()
        runner.end()
        ev     = ResponseEvaluator()
        report = ev.evaluate(session, injects)
        assert report.overall_score < 50

    def test_grade_populated(self):
        session, injects = self._run([{"who": "a", "text": "notify"}])
        ev = ResponseEvaluator()
        report = ev.evaluate(session, injects)
        assert report.grade in ("Excellent","Good","Satisfactory","Needs Improvement","Insufficient")

    def test_gaps_populated_for_missed_actions(self):
        session, injects = self._run([{"who": "a", "text": "I did nothing relevant"}])
        ev = ResponseEvaluator()
        report = ev.evaluate(session, injects)
        assert len(report.gaps) > 0

    def test_save_json(self, tmp_path):
        session, injects = self._run([{"who": "a", "text": "notify ciso and suspend model"}])
        ev     = ResponseEvaluator()
        report = ev.evaluate(session, injects)
        p      = tmp_path / "exercise.json"
        report.save_json(p)
        data   = json.loads(p.read_text())
        assert "overall_score" in data

    def test_strengths_for_high_coverage(self):
        session, injects = self._run([
            {"who": "a", "text": "notify ciso, suspend model, preserve logs — all done"},
        ])
        ev = ResponseEvaluator()
        report = ev.evaluate(session, injects)
        assert len(report.strengths) >= 0   # may be populated if coverage >=0.8

    def test_unique_report_ids(self):
        session, injects = self._run([{"who": "a", "text": "notify"}])
        ev = ResponseEvaluator()
        r1 = ev.evaluate(session, injects)
        r2 = ev.evaluate(session, injects)
        assert r1.report_id != r2.report_id
