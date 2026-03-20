"""
quarantine_pipeline.py  —  Request gate with audit logging
AI Fortress · Chapter 5 · Code Sample 5.C

Three-tier decision gate wrapping the EnsembleScorer:

  ALLOW   — score < review_threshold. Request passes to the LLM.
  REVIEW  — review_threshold ≤ score < block_threshold.
             Request is logged for human review; optionally passed through
             with a warning header injected into the system context.
  BLOCK   — score ≥ block_threshold. Request is rejected with a 400 response.
             Caller receives a generic refusal; detailed reason is audit-logged.

Every decision is written to a structured audit log (JSONL) recording:
  - request_id, timestamp, action, score, evidence, user_prompt hash,
    system_context hash, pattern matches, heuristic signals.

The user_prompt is NOT stored verbatim in the audit log — only its SHA-256
hash — to avoid storing potentially sensitive or adversarial content at rest.

Allow-list: regex patterns for prompts that should always ALLOW regardless
of score (e.g. internal test harnesses, known-good prompt templates).
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from ensemble_scorer import EnsembleScorer, EnsembleResult


@dataclass
class QuarantineDecision:
    request_id:    str
    action:        str          # "ALLOW" | "REVIEW" | "BLOCK"
    score:         float
    top_severity:  str
    evidence:      List[str]
    timestamp:     str
    prompt_hash:   str          # SHA-256 of user_prompt — not stored verbatim
    allowlisted:   bool = False


class QuarantinePipeline:
    """
    Injection detection gate for LLM API requests.

    Parameters
    ----------
    block_threshold    : Score ≥ this → BLOCK (default 0.75).
    review_threshold   : Score ≥ this → REVIEW (default 0.40).
    audit_log_path     : Optional path to JSONL audit log file.
    allow_patterns     : Regex patterns for prompts to always ALLOW.
    pass_review        : If True, REVIEW requests are passed through (default True).
    """

    def __init__(
        self,
        block_threshold:   float = 0.75,
        review_threshold:  float = 0.40,
        audit_log_path:    Optional[str | Path] = None,
        allow_patterns:    Optional[List[str]] = None,
        pass_review:       bool = True,
    ):
        self.block_threshold  = block_threshold
        self.review_threshold = review_threshold
        self.audit_log_path   = Path(audit_log_path) if audit_log_path else None
        self.pass_review      = pass_review
        self._scorer          = EnsembleScorer()
        self._allow_patterns  = [re.compile(p, re.IGNORECASE) for p in (allow_patterns or [])]
        self._decisions:      List[QuarantineDecision] = []

    def evaluate(
        self,
        user_prompt:    str,
        system_context: str = "",
    ) -> QuarantineDecision:
        """
        Evaluate a prompt and return a QuarantineDecision.
        Writes an audit entry regardless of action taken.
        """
        request_id  = "req_" + uuid.uuid4().hex[:16]
        timestamp   = datetime.now(timezone.utc).isoformat()
        prompt_hash = hashlib.sha256(user_prompt.encode("utf-8")).hexdigest()

        # ── Allow-list check ──────────────────────────────────────────────
        for pat in self._allow_patterns:
            if pat.search(user_prompt):
                decision = QuarantineDecision(
                    request_id   = request_id,
                    action       = "ALLOW",
                    score        = 0.0,
                    top_severity = "none",
                    evidence     = ["Matched allow-list pattern — bypassing detection."],
                    timestamp    = timestamp,
                    prompt_hash  = prompt_hash,
                    allowlisted  = True,
                )
                self._record(decision)
                return decision

        # ── Score the prompt ──────────────────────────────────────────────
        result: EnsembleResult = self._scorer.score(user_prompt, system_context)

        # ── Gate decision ─────────────────────────────────────────────────
        if result.score >= self.block_threshold:
            action = "BLOCK"
        elif result.score >= self.review_threshold:
            action = "REVIEW"
        else:
            action = "ALLOW"

        decision = QuarantineDecision(
            request_id   = request_id,
            action       = action,
            score        = result.score,
            top_severity = result.top_severity,
            evidence     = result.evidence,
            timestamp    = timestamp,
            prompt_hash  = prompt_hash,
        )
        self._record(decision)
        return decision

    def decisions(self) -> List[QuarantineDecision]:
        return list(self._decisions)

    def summary(self) -> dict:
        total   = len(self._decisions)
        if total == 0:
            return {"total": 0}
        return {
            "total":        total,
            "allowed":      sum(1 for d in self._decisions if d.action == "ALLOW"),
            "reviewed":     sum(1 for d in self._decisions if d.action == "REVIEW"),
            "blocked":      sum(1 for d in self._decisions if d.action == "BLOCK"),
            "allowlisted":  sum(1 for d in self._decisions if d.allowlisted),
            "block_rate":   round(sum(1 for d in self._decisions if d.action == "BLOCK") / total, 4),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _record(self, decision: QuarantineDecision) -> None:
        self._decisions.append(decision)
        if self.audit_log_path:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(decision)) + "\n")
