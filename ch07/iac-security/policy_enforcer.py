"""
policy_enforcer.py  —  Policy-as-code rule engine and findings report
AI Fortress · Chapter 7 · Code Sample 7.A

Takes a list of Finding objects from any scanner and:
  1. Groups findings by severity and rule_id
  2. Generates a structured JSON + Markdown report
  3. Enforces a pass/fail gate — raises PolicyViolationError if findings
     at or above the configured severity threshold are present
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from terraform_scanner import Finding


class PolicyViolationError(RuntimeError):
    """Raised when findings exceed the configured severity gate."""
    def __init__(self, message: str, critical: int, high: int):
        super().__init__(message)
        self.critical = critical
        self.high     = high


_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class ScanReport:
    scanner:    str
    total:      int
    critical:   int
    high:       int
    medium:     int
    low:        int
    findings:   List[Finding]
    passed:     bool    # True if no findings at or above gate threshold

    def save_json(self, path: str | Path) -> None:
        data = {
            "scanner":  self.scanner,
            "total":    self.total,
            "critical": self.critical,
            "high":     self.high,
            "medium":   self.medium,
            "low":      self.low,
            "passed":   self.passed,
            "findings": [
                {
                    "rule_id":       f.rule_id,
                    "severity":      f.severity,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "description":   f.description,
                    "remediation":   f.remediation,
                    "compliance":    f.compliance,
                }
                for f in self.findings
            ],
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def save_markdown(self, path: str | Path) -> None:
        Path(path).write_text(self._to_markdown(), encoding="utf-8")

    def _to_markdown(self) -> str:
        verdict = "✅ PASSED" if self.passed else "❌ FAILED"
        lines   = [
            f"# IaC Security Scan Report — {verdict}",
            f"**Scanner:** {self.scanner}  ",
            f"**Total findings:** {self.total} "
            f"(🔴 {self.critical} critical, 🟠 {self.high} high, "
            f"🟡 {self.medium} medium, ⚪ {self.low} low)",
            "",
            "| Rule | Severity | Resource | Description |",
            "|------|----------|----------|-------------|",
        ]
        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
        for f in sorted(self.findings, key=lambda x: _SEVERITY_ORDER.get(x.severity, 0), reverse=True):
            icon = sev_icon.get(f.severity, "")
            desc = f.description[:100].replace("|", "│")
            lines.append(
                f"| `{f.rule_id}` | {icon} {f.severity} | `{f.resource_name}` | {desc} |"
            )
        if self.findings:
            lines += ["", "## Remediation Details", ""]
            for f in self.findings:
                lines += [
                    f"### `{f.rule_id}` — {f.resource_name}",
                    f"**Severity:** {f.severity}  ",
                    f"**Description:** {f.description}  ",
                    f"**Remediation:** {f.remediation}  ",
                    f"**Compliance:** {', '.join(f.compliance)}",
                    "",
                ]
        return "\n".join(lines)


class PolicyEnforcer:
    """
    Enforces a severity gate on scanner findings.

    Parameters
    ----------
    fail_on_severity : Severity level at which the gate fails ("CRITICAL" | "HIGH" | "MEDIUM")
    scanner_name     : Label for the report
    """

    def __init__(
        self,
        fail_on_severity: str = "CRITICAL",
        scanner_name:     str = "iac-scanner",
    ):
        self.fail_on_severity = fail_on_severity
        self.scanner_name     = scanner_name
        self._gate_level      = _SEVERITY_ORDER.get(fail_on_severity, 4)

    def build_report(self, findings: List[Finding]) -> ScanReport:
        counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        gate_breach = any(
            _SEVERITY_ORDER.get(f.severity, 0) >= self._gate_level
            for f in findings
        )
        return ScanReport(
            scanner  = self.scanner_name,
            total    = len(findings),
            critical = counts["CRITICAL"],
            high     = counts["HIGH"],
            medium   = counts["MEDIUM"],
            low      = counts["LOW"],
            findings = findings,
            passed   = not gate_breach,
        )

    def enforce(self, findings: List[Finding]) -> ScanReport:
        """
        Build report and raise PolicyViolationError if gate is breached.
        """
        report = self.build_report(findings)
        if not report.passed:
            raise PolicyViolationError(
                f"IaC policy gate FAILED: {report.critical} CRITICAL, "
                f"{report.high} HIGH finding(s). Fix before deploying.",
                critical = report.critical,
                high     = report.high,
            )
        return report
