"""
licence_policy_gate.py  —  Organisation-wide licence policy gate for SBOMs
AI Fortress · Chapter 8 · Code Sample 8.E

Enforces an organisation-wide licence policy against all components in a
CycloneDX SBOM.  Raises LicencePolicyError if any denied or unknown licences
are present; returns a structured PolicyReport otherwise.

Default policy (same categories as licence_checker.py in 8.B, but applied
at the SBOM level rather than the per-environment level so that governance
teams can gate artefact promotion pipelines):

  ALLOWED     — MIT, Apache-2.0, BSD-*, ISC, PSF-2.0, LGPL-2.1, CC0-1.0, …
  RESTRICTED  — GPL-*, LGPL-3.0, MPL-2.0, EUPL-1.2  (require legal sign-off)
  DENIED      — AGPL-3.0, SSPL-1.0, BUSL-1.1, Commons-Clause
  UNKNOWN     — NOASSERTION, "" (must be resolved before promotion)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


_DEFAULT_ALLOWED = {
    "MIT", "Apache-2.0", "Apache-2", "Apache 2.0",
    "BSD-2-Clause", "BSD-3-Clause", "BSD",
    "ISC", "PSF-2.0", "Python-2.0", "Unlicense",
    "CC0-1.0", "WTFPL", "Zlib", "libpng", "OpenSSL",
    "LGPL-2.1", "LGPL-2.1-only",
}

_DEFAULT_RESTRICTED = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-3.0", "LGPL-3.0-only",
    "MPL-2.0", "EUPL-1.2", "CDDL-1.0", "EPL-2.0",
}

_DEFAULT_DENIED = {
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0", "BUSL-1.1", "Commons-Clause", "BSL-1.0",
}

_UNKNOWN_TOKENS = {"NOASSERTION", "UNKNOWN", "", "NONE", "OTHER"}


@dataclass
class LicencePolicyFinding:
    component:   str
    version:     str
    licence:     str
    status:      str          # ALLOWED | RESTRICTED | DENIED | UNKNOWN
    severity:    str          # INFO | MEDIUM | CRITICAL | HIGH
    message:     str


@dataclass
class LicencePolicyReport:
    project:         str
    total_components: int
    allowed:         int
    restricted:      int
    denied:          int
    unknown:         int
    findings:        List[LicencePolicyFinding]
    passed:          bool

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.passed else "❌"
        return (
            f"{icon} Licence policy '{self.project}': "
            f"{self.allowed} allowed, {self.restricted} restricted, "
            f"{self.denied} denied, {self.unknown} unknown."
        )


class LicencePolicyError(RuntimeError):
    """Raised when the licence policy gate is breached."""
    def __init__(self, report: "LicencePolicyReport"):
        denied_names  = [f.component for f in report.findings if f.status == "DENIED"]
        unknown_names = [f.component for f in report.findings if f.status == "UNKNOWN"]
        super().__init__(
            f"Licence policy FAILED for '{report.project}': "
            f"{report.denied} denied ({denied_names}), "
            f"{report.unknown} unknown ({unknown_names})."
        )
        self.report = report


class LicencePolicyGate:
    """
    Enforces an organisation licence policy against a CycloneDX SBOM.

    Parameters
    ----------
    allowed     : Set of allowed SPDX licence identifiers.
    restricted  : Copyleft licences that require legal sign-off.
    denied      : Licences incompatible with commercial/SaaS deployment.
    block_restricted : If True, restricted licences also fail the gate
                       (default False — they generate warnings only).
    """

    def __init__(
        self,
        allowed:          Optional[Set[str]] = None,
        restricted:       Optional[Set[str]] = None,
        denied:           Optional[Set[str]] = None,
        block_restricted: bool = False,
    ):
        self.allowed          = {s.upper() for s in (allowed    or _DEFAULT_ALLOWED)}
        self.restricted       = {s.upper() for s in (restricted or _DEFAULT_RESTRICTED)}
        self.denied           = {s.upper() for s in (denied     or _DEFAULT_DENIED)}
        self.block_restricted = block_restricted

    def check(self, sbom: dict) -> LicencePolicyReport:
        """Evaluate a CycloneDX SBOM dict against the licence policy."""
        project    = (sbom.get("metadata", {}).get("component", {}) or {}).get("name", "unknown")
        components = sbom.get("components", [])
        findings:  List[LicencePolicyFinding] = []
        counts     = {"ALLOWED": 0, "RESTRICTED": 0, "DENIED": 0, "UNKNOWN": 0}

        for comp in components:
            name    = comp.get("name", "unknown")
            version = comp.get("version", "")
            lics    = comp.get("licenses", []) or []
            lic     = lics[0].get("license", {}).get("id", "") if lics else ""
            lic_up  = lic.strip().upper()

            if not lic.strip() or lic_up in _UNKNOWN_TOKENS:
                status, sev, msg = (
                    "UNKNOWN", "HIGH",
                    f"Component '{name}' has no licence declared. "
                    "Cannot assess compatibility — resolve before promotion.",
                )
            elif lic_up in self.denied:
                status, sev, msg = (
                    "DENIED", "CRITICAL",
                    f"'{name}' uses '{lic}' which is denied by organisational policy. "
                    "Remove or replace before promotion.",
                )
            elif lic_up in self.restricted:
                status, sev, msg = (
                    "RESTRICTED", "MEDIUM",
                    f"'{name}' uses copyleft licence '{lic}'. "
                    "Legal sign-off required before production deployment.",
                )
            else:
                status, sev, msg = "ALLOWED", "INFO", f"'{name}' licence '{lic}' is allowed."

            counts[status] += 1
            if status != "ALLOWED":
                findings.append(LicencePolicyFinding(
                    component = name,
                    version   = version,
                    licence   = lic,
                    status    = status,
                    severity  = sev,
                    message   = msg,
                ))

        blocked = counts["DENIED"] > 0 or counts["UNKNOWN"] > 0
        if self.block_restricted:
            blocked = blocked or counts["RESTRICTED"] > 0

        return LicencePolicyReport(
            project          = project,
            total_components = len(components),
            allowed          = counts["ALLOWED"],
            restricted       = counts["RESTRICTED"],
            denied           = counts["DENIED"],
            unknown          = counts["UNKNOWN"],
            findings         = findings,
            passed           = not blocked,
        )

    def enforce(self, sbom: dict) -> LicencePolicyReport:
        """Run check() and raise LicencePolicyError if gate is breached."""
        report = self.check(sbom)
        if not report.passed:
            raise LicencePolicyError(report)
        return report
