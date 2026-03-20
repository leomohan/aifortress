"""
heuristic_analyser.py  —  Structural prompt property analysis
AI Fortress · Chapter 5 · Code Sample 5.C

Analyses prompt structure and statistics for injection signals that evade
simple pattern matching:

  1. Length anomaly       — user prompt disproportionately longer than system
                            context (attacker trying to dilute system prompt)
  2. Imperative density   — high fraction of imperative verbs (do, tell, show,
                            reveal, ignore, forget, pretend, act, respond, output)
  3. Special token density — high density of punctuation/symbols used as
                            delimiters in injection attempts
  4. Language switch       — abrupt change in script/language mid-prompt
                            (used to bypass language-specific filters)
  5. Instruction repetition — same instruction rephrased multiple times
                            (persistence attack against safety filters)
  6. Unicode anomaly       — unusual Unicode categories (private use area,
                            homoglyph substitutions, right-to-left override)
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class HeuristicFinding:
    signal:      str     # heuristic name
    score:       float   # contribution to injection probability [0, 1]
    detail:      str     # human-readable explanation


@dataclass
class HeuristicReport:
    findings:    List[HeuristicFinding]
    total_score: float                   # weighted combination [0, 1]

    @property
    def signals(self) -> List[str]:
        return [f.signal for f in self.findings if f.score > 0]


# Imperative verbs commonly used in injection attempts
_IMPERATIVE_WORDS = re.compile(
    r"\b(ignore|forget|disregard|override|bypass|reveal|output|print|show|"
    r"display|tell|repeat|act|pretend|behave|respond|answer|do|execute|run|"
    r"perform|enable|activate|switch|enter|become|transform)\b",
    re.IGNORECASE,
)

# Special characters used as injection delimiters
_SPECIAL_TOKENS = re.compile(r"[<>\[\]{}/\\|`~@#$%^&*]")

# Unicode private use or unusual ranges
_UNICODE_ANOMALY = re.compile(
    r"[\uE000-\uF8FF\u202A-\u202E\u2066-\u2069\u200B-\u200F\uFFF0-\uFFFF]"
)


class HeuristicAnalyser:
    """
    Computes structural injection signals from prompt text.

    Parameters
    ----------
    length_ratio_threshold   : user/system length ratio above which signal fires
    imperative_density_threshold : fraction of words that are imperative verbs
    special_token_density_threshold : fraction of chars that are special tokens
    """

    def __init__(
        self,
        length_ratio_threshold:           float = 5.0,
        imperative_density_threshold:     float = 0.12,
        special_token_density_threshold:  float = 0.08,
        repetition_similarity_threshold:  float = 0.70,
    ):
        self.length_ratio_threshold          = length_ratio_threshold
        self.imperative_density_threshold    = imperative_density_threshold
        self.special_token_density_threshold = special_token_density_threshold
        self.repetition_similarity_threshold = repetition_similarity_threshold

    def analyse(
        self,
        user_prompt:    str,
        system_context: str = "",
    ) -> HeuristicReport:
        findings: List[HeuristicFinding] = []

        findings.append(self._length_anomaly(user_prompt, system_context))
        findings.append(self._imperative_density(user_prompt))
        findings.append(self._special_token_density(user_prompt))
        findings.append(self._unicode_anomaly(user_prompt))
        findings.append(self._language_switch(user_prompt))
        findings.append(self._instruction_repetition(user_prompt))

        findings = [f for f in findings if f is not None]

        # Weighted combination — signals are complementary, not additive
        if not findings:
            total = 0.0
        else:
            scores = [f.score for f in findings]
            # Take max plus a diminishing bonus for co-occurring signals
            total = max(scores) + 0.05 * sum(s for s in sorted(scores)[:-1]) / max(len(scores) - 1, 1)
            total = min(total, 1.0)

        return HeuristicReport(findings=findings, total_score=round(total, 4))

    # ── Individual heuristics ─────────────────────────────────────────────────

    def _length_anomaly(self, user: str, system: str) -> HeuristicFinding:
        u_len = len(user)
        s_len = len(system) if system else 1
        ratio = u_len / s_len
        if ratio > self.length_ratio_threshold and u_len > 500:
            score = min(0.60, 0.20 + 0.05 * (ratio - self.length_ratio_threshold))
            return HeuristicFinding(
                signal = "length_anomaly",
                score  = round(score, 4),
                detail = f"User prompt is {ratio:.1f}× longer than system context "
                         f"({u_len} vs {s_len} chars) — possible context dilution attack.",
            )
        return HeuristicFinding("length_anomaly", 0.0, "Within normal length ratio.")

    def _imperative_density(self, prompt: str) -> HeuristicFinding:
        words      = prompt.split()
        if not words:
            return HeuristicFinding("imperative_density", 0.0, "Empty prompt.")
        imperatives = len(_IMPERATIVE_WORDS.findall(prompt))
        density     = imperatives / len(words)
        if density > self.imperative_density_threshold:
            score = min(0.70, density * 4.0)
            return HeuristicFinding(
                signal = "imperative_density",
                score  = round(score, 4),
                detail = f"High imperative verb density: {density:.1%} "
                         f"({imperatives}/{len(words)} words).",
            )
        return HeuristicFinding("imperative_density", 0.0, f"Imperative density {density:.1%} normal.")

    def _special_token_density(self, prompt: str) -> HeuristicFinding:
        if not prompt:
            return HeuristicFinding("special_token_density", 0.0, "Empty prompt.")
        n_special = len(_SPECIAL_TOKENS.findall(prompt))
        density   = n_special / len(prompt)
        if density > self.special_token_density_threshold:
            score = min(0.55, density * 5.0)
            return HeuristicFinding(
                signal = "special_token_density",
                score  = round(score, 4),
                detail = f"High special character density: {density:.1%} "
                         f"({n_special}/{len(prompt)} chars) — possible delimiter injection.",
            )
        return HeuristicFinding("special_token_density", 0.0, f"Special token density {density:.1%} normal.")

    def _unicode_anomaly(self, prompt: str) -> HeuristicFinding:
        anomalies = _UNICODE_ANOMALY.findall(prompt)
        if anomalies:
            score = min(0.80, 0.30 + 0.10 * len(anomalies))
            return HeuristicFinding(
                signal = "unicode_anomaly",
                score  = round(score, 4),
                detail = f"Found {len(anomalies)} unusual Unicode characters "
                         "(private use area, RTL override, zero-width chars) — possible homoglyph attack.",
            )
        return HeuristicFinding("unicode_anomaly", 0.0, "No Unicode anomalies detected.")

    def _language_switch(self, prompt: str) -> HeuristicFinding:
        """Detect abrupt script changes (e.g. Latin → Cyrillic mid-sentence)."""
        scripts: List[str] = []
        for ch in prompt:
            if ch.isalpha():
                try:
                    name = unicodedata.name(ch, "")
                    script = name.split()[0] if name else "UNKNOWN"
                    if not scripts or scripts[-1] != script:
                        scripts.append(script)
                except Exception:
                    pass

        latin_scripts = {"LATIN", "DIGIT"}
        foreign_scripts = [s for s in scripts if s not in latin_scripts and s != "UNKNOWN"]
        if len(set(scripts)) >= 3 and foreign_scripts:
            return HeuristicFinding(
                signal = "language_switch",
                score  = 0.45,
                detail = f"Script changes detected across {len(set(scripts))} scripts "
                         f"({', '.join(list(set(scripts))[:5])}) — possible filter bypass via language switch.",
            )
        return HeuristicFinding("language_switch", 0.0, "No unusual script switches detected.")

    def _instruction_repetition(self, prompt: str) -> HeuristicFinding:
        """Detect the same instruction rephrased multiple times (persistence attack)."""
        sentences = [s.strip() for s in re.split(r"[.!?\n]+", prompt) if len(s.strip()) > 20]
        if len(sentences) < 3:
            return HeuristicFinding("instruction_repetition", 0.0, "Too few sentences to assess.")

        # Simple bigram overlap similarity between non-adjacent sentences
        def bigrams(text: str):
            words = text.lower().split()
            return set(zip(words, words[1:]))

        repetition_pairs = 0
        for i in range(len(sentences)):
            for j in range(i + 2, len(sentences)):  # skip adjacent
                bg_i = bigrams(sentences[i])
                bg_j = bigrams(sentences[j])
                if not bg_i or not bg_j:
                    continue
                overlap = len(bg_i & bg_j) / min(len(bg_i), len(bg_j))
                if overlap >= self.repetition_similarity_threshold:
                    repetition_pairs += 1

        if repetition_pairs >= 2:
            score = min(0.65, 0.30 + 0.10 * repetition_pairs)
            return HeuristicFinding(
                signal = "instruction_repetition",
                score  = round(score, 4),
                detail = f"Detected {repetition_pairs} pairs of similar non-adjacent instructions "
                         "— possible persistence attack against safety filters.",
            )
        return HeuristicFinding("instruction_repetition", 0.0, "No significant instruction repetition.")
