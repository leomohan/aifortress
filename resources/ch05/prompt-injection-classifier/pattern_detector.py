"""
pattern_detector.py  —  Prompt injection signature pattern matching
AI Fortress · Chapter 5 · Code Sample 5.C

Detects known prompt injection and jailbreak patterns using a tiered
signature library. Patterns are organised by attack class and severity:

  CRITICAL  — direct instruction overrides, system prompt exfiltration,
               role hijacking (DAN, jailbreak personas)
  HIGH      — goal redirection, constraint removal, output format hijacking
  MEDIUM    — indirect injection markers, social engineering preambles,
               adversarial suffix patterns
  LOW       — suspicious structural markers, unusual delimiters

All patterns are case-insensitive. The detector returns the first N matches
with their severity and matched text for use in audit logs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PatternMatch:
    pattern_id:  str
    severity:    str        # "critical" | "high" | "medium" | "low"
    category:    str        # "instruction_override" | "role_hijack" | etc.
    matched_text: str
    position:    int        # character offset in prompt


# ── Signature library ─────────────────────────────────────────────────────────

SIGNATURES = [
    # ── CRITICAL: direct instruction overrides ────────────────────────────
    ("PI-001", "critical", "instruction_override",
     r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)"),
    ("PI-002", "critical", "instruction_override",
     r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|constraints?)"),
    ("PI-003", "critical", "instruction_override",
     r"forget\s+(everything|all)\s+(you\s+)?(were\s+)?(told|instructed|given)"),
    ("PI-004", "critical", "instruction_override",
     r"(your\s+)?(new|real|actual|true)\s+(instructions?|task|goal|purpose|objective)\s+(is|are|:)"),
    ("PI-005", "critical", "system_exfiltration",
     r"(print|reveal|show|output|repeat|display|tell me)\s+(your\s+)?(system\s+prompt|instructions?|configuration|initial\s+prompt)"),
    ("PI-006", "critical", "system_exfiltration",
     r"what\s+(are|were)\s+(your\s+)?(original\s+)?(instructions?|system\s+prompt|initial\s+message)"),

    # ── CRITICAL: role hijacking and persona injection ─────────────────────
    ("PI-007", "critical", "role_hijack",
     r"\b(DAN|DUDE|AIM|STAN|KEVIN|JAILBREAK|UCAR)\b"),
    ("PI-008", "critical", "role_hijack",
     r"you\s+are\s+now\s+(?!a\s+helpful).{0,60}(without\s+(any\s+)?(restrictions?|limits?|filters?|ethics?|morals?))"),
    ("PI-009", "critical", "role_hijack",
     r"(pretend|act|behave|respond)\s+(as\s+if\s+you\s+(are|were)|like)\s+(?!a\s+helpful).{0,80}(no\s+restrictions?|unrestricted|uncensored|without\s+limit)"),
    ("PI-010", "critical", "role_hijack",
     r"(enable|activate|switch\s+to|enter)\s+(developer|jailbreak|god|unrestricted|admin)\s+mode"),

    # ── HIGH: goal redirection ─────────────────────────────────────────────
    ("PI-011", "high", "goal_redirection",
     r"instead\s+of\s+(that|this|the\s+above|what\s+i\s+said)\s*[,.]?\s*(do|perform|execute|complete)"),
    ("PI-012", "high", "goal_redirection",
     r"(your\s+)?(primary|main|only|real)\s+(goal|objective|task|purpose)\s+(is\s+now|should\s+be|must\s+be)"),
    ("PI-013", "high", "constraint_removal",
     r"(remove|disable|bypass|ignore|skip)\s+(all\s+)?(safety|content|ethical?)\s+(filter|check|guard|restriction|policy|rule)"),
    ("PI-014", "high", "constraint_removal",
     r"(do\s+not\s+|don'?t\s+)(apply|use|follow|enforce)\s+(your\s+)?(safety|ethical?|content)\s+(policy|rules?|guidelines?|filter)"),
    ("PI-015", "high", "output_hijack",
     r"(output|respond|answer|reply)\s+(only\s+)?(in\s+)?(the\s+)?(format|following|way)\s*:?\s*\[?[A-Z_]{5,}\]?"),

    # ── MEDIUM: indirect injection and social engineering ──────────────────
    ("PI-016", "medium", "indirect_injection",
     r"<(system|assistant|instruction|context|prompt|user)>\s*.{0,200}\s*</(system|assistant|instruction|context|prompt|user)>"),
    ("PI-017", "medium", "indirect_injection",
     r"\[\s*(SYSTEM|INST|INSTRUCTION|OVERRIDE|ADMIN)\s*\]"),
    ("PI-018", "medium", "social_engineering",
     r"(for\s+(educational|research|academic|testing|hypothetical)\s+purposes?\s+(only\s+)?,?\s*(pretend|assume|imagine|suppose))"),
    ("PI-019", "medium", "social_engineering",
     r"(hypothetically|theoretically|in\s+a\s+fictional\s+(scenario|story|world))\s*,?\s*(how\s+would|what\s+if)"),
    ("PI-020", "medium", "adversarial_suffix",
     r"(\s+\|\||\s+&&|\s+;\s*)\s*(echo|cat|ls|rm|wget|curl|python|bash|sh)\s"),

    # ── LOW: structural markers ────────────────────────────────────────────
    ("PI-021", "low", "delimiter_abuse",
     r"(---+|===+|###|~~~)\s*(end\s+of\s+(system|user|assistant)|begin\s+(injection|override))"),
    ("PI-022", "low", "delimiter_abuse",
     r"```\s*(system|override|inject|admin)\s*\n"),
    ("PI-023", "low", "repetition_attack",
     r"(.{10,50})\1{3,}"),   # same substring repeated 3+ times
]

_COMPILED = [
    (pid, sev, cat, re.compile(pat, re.IGNORECASE | re.DOTALL))
    for pid, sev, cat, pat in SIGNATURES
]


class PatternDetector:
    """
    Matches prompts against the injection signature library.

    Parameters
    ----------
    max_matches    : Maximum number of matches to return (default 10).
    custom_patterns: Additional (pattern_id, severity, category, regex_str) tuples.
    """

    def __init__(
        self,
        max_matches:     int = 10,
        custom_patterns: Optional[List[tuple]] = None,
    ):
        self.max_matches = max_matches
        self._patterns   = list(_COMPILED)
        if custom_patterns:
            for pid, sev, cat, pat in custom_patterns:
                self._patterns.append((pid, sev, cat, re.compile(pat, re.IGNORECASE | re.DOTALL)))

    def detect(self, prompt: str) -> List[PatternMatch]:
        """
        Scan `prompt` and return all pattern matches up to max_matches.
        Returns empty list if no injection signatures found.
        """
        matches: List[PatternMatch] = []
        for pid, sev, cat, rx in self._patterns:
            m = rx.search(prompt)
            if m:
                matches.append(PatternMatch(
                    pattern_id   = pid,
                    severity     = sev,
                    category     = cat,
                    matched_text = prompt[m.start(): min(m.end(), m.start() + 120)],
                    position     = m.start(),
                ))
                if len(matches) >= self.max_matches:
                    break
        return matches

    def score(self, prompt: str) -> float:
        """
        Return a raw injection score in [0, 1] based on pattern matches.
        Critical matches contribute more heavily than lower-severity ones.
        """
        matches = self.detect(prompt)
        if not matches:
            return 0.0

        severity_weight = {"critical": 0.90, "high": 0.65, "medium": 0.40, "low": 0.15}
        raw = max(severity_weight.get(m.severity, 0.1) for m in matches)
        # Boost if multiple matches
        boost = min(0.10 * (len(matches) - 1), 0.20)
        return min(raw + boost, 1.0)
