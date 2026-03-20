"""
response_evaluator.py  —  Tabletop exercise response evaluator
AI Fortress · Chapter 17 · Code Sample 17.E

Evaluates participant responses against expected actions for each inject.
Produces a scored exercise report with gaps and observations.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from scenario_runner import ExerciseSession, Inject, ParticipantResponse


@dataclass
class InjectEvaluation:
    inject_id:      str
    inject_title:   str
    expected_count: int
    responses:      List[ParticipantResponse]
    keywords_hit:   List[str]    # expected actions mentioned in responses
    keywords_missed: List[str]   # expected actions not mentioned
    coverage:       float        # 0–1
    observations:   List[str]


@dataclass
class ExerciseReport:
    report_id:         str
    session_id:        str
    scenario_name:     str
    overall_score:     float    # 0–100
    grade:             str      # "Excellent"|"Good"|"Satisfactory"|"Needs Improvement"|"Insufficient"
    inject_evals:      List[InjectEvaluation]
    strengths:         List[str]
    gaps:              List[str]
    recommendations:   List[str]
    generated_at:      str

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class ResponseEvaluator:
    """
    Evaluates tabletop exercise responses against inject expected actions.

    Scoring: keyword coverage — each expected action keyword found in
    participant responses contributes equally to the inject score.
    Overall score = mean coverage across all injects × 100.
    """

    def evaluate(
        self,
        session:  ExerciseSession,
        injects:  List[Inject],
    ) -> ExerciseReport:
        inject_map = {i.inject_id: i for i in injects}
        resp_map:  Dict[str, List[ParticipantResponse]] = {}
        for r in session.responses:
            resp_map.setdefault(r.inject_id, []).append(r)

        evals: List[InjectEvaluation] = []
        for inj in injects:
            responses  = resp_map.get(inj.inject_id, [])
            all_text   = " ".join(r.response_text.lower() for r in responses)
            expected   = [a.lower() for a in inj.expected_actions]
            hit        = [a for a in expected if any(
                kw in all_text for kw in a.split()[:3]
            )]
            missed     = [a for a in expected if a not in hit]
            coverage   = (len(hit) / len(expected)) if expected else 1.0
            obs        = []
            if not responses:
                obs.append(f"No response recorded for inject '{inj.title}'.")
            if coverage < 0.5:
                obs.append(f"Low coverage ({coverage:.0%}) — key actions missed.")
            evals.append(InjectEvaluation(
                inject_id      = inj.inject_id,
                inject_title   = inj.title,
                expected_count = len(expected),
                responses      = responses,
                keywords_hit   = hit,
                keywords_missed = missed,
                coverage       = round(coverage, 4),
                observations   = obs,
            ))

        overall = round(
            (sum(e.coverage for e in evals) / len(evals) * 100) if evals else 0.0,
            1
        )
        grade = (
            "Excellent"         if overall >= 85 else
            "Good"              if overall >= 70 else
            "Satisfactory"      if overall >= 55 else
            "Needs Improvement" if overall >= 40 else
            "Insufficient"
        )

        strengths = [
            f"Inject '{e.inject_title}' coverage: {e.coverage:.0%}"
            for e in evals if e.coverage >= 0.8
        ]
        gaps = [
            f"Inject '{e.inject_title}' missed: {', '.join(e.keywords_missed[:2])}"
            for e in evals if e.keywords_missed
        ]
        recs: List[str] = []
        if overall < 70:
            recs.append("Schedule follow-up drill focusing on low-coverage injects.")
        if any(not e.responses for e in evals):
            recs.append("Ensure all team members respond to every inject.")
        if not recs:
            recs.append("Maintain current response quality. Consider harder scenario variants.")

        return ExerciseReport(
            report_id      = str(uuid.uuid4())[:8],
            session_id     = session.session_id,
            scenario_name  = session.scenario_name,
            overall_score  = overall,
            grade          = grade,
            inject_evals   = evals,
            strengths      = strengths,
            gaps           = gaps,
            recommendations = recs,
            generated_at   = datetime.now(timezone.utc).isoformat(),
        )
