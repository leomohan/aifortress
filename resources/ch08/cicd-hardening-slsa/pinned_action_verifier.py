"""
pinned_action_verifier.py  —  GitHub Actions SHA pin verification
AI Fortress · Chapter 8 · Code Sample 8.D

Scans GitHub Actions workflow YAML files and flags any `uses:` reference
not pinned to a full 40-character SHA1 commit hash.

Mutable references that are flagged:
  - Branch tags:  actions/checkout@main
  - Version tags: actions/checkout@v3, actions/checkout@v3.5.2
  - No pin:       actions/checkout (no @)

Safe (pinned) references:
  - actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


_SHA1_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_USES_RE  = re.compile(r"^\s*-?\s*uses:\s*(.+)$", re.MULTILINE)


@dataclass
class UnpinnedAction:
    workflow_file: str
    action:        str           # e.g. "actions/checkout@v3"
    line_number:   int
    severity:      str           # "HIGH" (mutable tag) | "CRITICAL" (no pin)
    suggestion:    str           # "Pin to a full SHA1 commit hash"


@dataclass
class PinVerifyReport:
    total_actions: int
    pinned:        int
    unpinned:      int
    findings:      List[UnpinnedAction]
    overall_pass:  bool

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} Action pins: {self.pinned}/{self.total_actions} pinned. "
            f"{self.unpinned} unpinned action(s) detected."
        )


class PinnedActionVerifier:
    """Scans GitHub Actions workflow files for unpinned action references."""

    def verify_file(self, path: str | Path) -> PinVerifyReport:
        text = Path(path).read_text(encoding="utf-8")
        return self._verify_text(text, str(path))

    def verify_directory(self, workflows_dir: str | Path) -> PinVerifyReport:
        """Scan all .yml/.yaml files under a workflows directory."""
        all_findings: List[UnpinnedAction] = []
        total = pinned = 0

        for wf in Path(workflows_dir).glob("**/*.yml"):
            report = self.verify_file(wf)
            total  += report.total_actions
            pinned += report.pinned
            all_findings.extend(report.findings)
        for wf in Path(workflows_dir).glob("**/*.yaml"):
            report = self.verify_file(wf)
            total  += report.total_actions
            pinned += report.pinned
            all_findings.extend(report.findings)

        return PinVerifyReport(
            total_actions = total,
            pinned        = pinned,
            unpinned      = total - pinned,
            findings      = all_findings,
            overall_pass  = len(all_findings) == 0,
        )

    def _verify_text(self, text: str, source: str) -> PinVerifyReport:
        findings: List[UnpinnedAction] = []
        lines = text.splitlines()
        total = 0

        for i, line in enumerate(lines, 1):
            m = re.match(r"^\s*-?\s*uses:\s*(.+)$", line)
            if not m:
                continue
            action = m.group(1).strip().strip('"\'')
            # Skip local path references (./) and docker:// references
            if action.startswith("./") or action.startswith("docker://"):
                continue
            total += 1

            if "@" not in action:
                findings.append(UnpinnedAction(
                    workflow_file = source,
                    action        = action,
                    line_number   = i,
                    severity      = "CRITICAL",
                    suggestion    = "Add @<full-sha1> pin to this action reference.",
                ))
                continue

            ref = action.split("@", 1)[1].strip()
            if not _SHA1_RE.match(ref):
                findings.append(UnpinnedAction(
                    workflow_file = source,
                    action        = action,
                    line_number   = i,
                    severity      = "HIGH",
                    suggestion    = f"Replace '@{ref}' with the full SHA1 of that ref.",
                ))

        pinned = total - len(findings)
        return PinVerifyReport(
            total_actions = total,
            pinned        = pinned,
            unpinned      = len(findings),
            findings      = findings,
            overall_pass  = len(findings) == 0,
        )
