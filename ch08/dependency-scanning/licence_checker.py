"""
licence_checker.py  —  Licence policy compliance for ML dependencies
AI Fortress · Chapter 8 · Code Sample 8.B

Classifies each package licence against a configurable policy:
  ALLOWED     — permissive licences compatible with commercial ML products
  RESTRICTED  — copyleft licences requiring legal review before inclusion
  DENIED      — licences incompatible with the project's distribution model
  UNKNOWN     — licence could not be determined (requires manual review)

Default policy for commercial ML products:
  Allowed:    MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, PSF-2.0,
              Unlicense, CC0-1.0, LGPL-2.1 (dynamic linking OK)
  Restricted: GPL-2.0, GPL-3.0, LGPL-3.0, MPL-2.0, EUPL-1.2
              (require legal review — may require open-sourcing the model)
  Denied:     AGPL-3.0, SSPL-1.0, Commons-Clause
              (incompatible with SaaS deployment of ML APIs)
  Unknown:    NOASSERTION, UNKNOWN, "" (must be manually reviewed)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


_DEFAULT_ALLOWED = {
    "MIT", "Apache-2.0", "Apache-2", "Apache 2.0",
    "BSD-2-Clause", "BSD-3-Clause", "BSD",
    "ISC", "PSF-2.0", "Python-2.0",
    "Unlicense", "CC0-1.0", "WTFPL",
    "LGPL-2.1", "LGPL-2.1-only",
    "Zlib", "libpng", "OpenSSL",
}

_DEFAULT_RESTRICTED = {
    "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    "LGPL-3.0", "LGPL-3.0-only",
    "MPL-2.0", "EUPL-1.2", "CDDL-1.0", "EPL-2.0",
}

_DEFAULT_DENIED = {
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "SSPL-1.0", "Commons-Clause", "BSL-1.0",
    "BUSL-1.1",
}

_UNKNOWN_TOKENS = {"NOASSERTION", "UNKNOWN", "", "NONE", "OTHER", "SEE LICENSE IN README"}


@dataclass
class LicenceFinding:
    check_id:    str
    severity:    str
    package:     str
    version:     str
    licence:     str
    status:      str        # "ALLOWED" | "RESTRICTED" | "DENIED" | "UNKNOWN"
    description: str
    action:      str        # required action


@dataclass
class LicenceReport:
    total_packages: int
    allowed:        int
    restricted:     int
    denied:         int
    unknown:        int
    findings:       List[LicenceFinding]
    overall_pass:   bool    # True if no DENIED or UNKNOWN findings

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} Licence: {self.allowed} allowed, {self.restricted} restricted, "
            f"{self.denied} denied, {self.unknown} unknown."
        )


class LicenceChecker:
    """
    Checks package licences against a configurable policy.

    Parameters
    ----------
    allowed     : Set of allowed licence SPDX identifiers
    restricted  : Set of restricted licence identifiers (require legal review)
    denied      : Set of denied licence identifiers
    """

    def __init__(
        self,
        allowed:    Optional[Set[str]] = None,
        restricted: Optional[Set[str]] = None,
        denied:     Optional[Set[str]] = None,
    ):
        self.allowed    = allowed    if allowed    is not None else _DEFAULT_ALLOWED
        self.restricted = restricted if restricted is not None else _DEFAULT_RESTRICTED
        self.denied     = denied     if denied     is not None else _DEFAULT_DENIED

    def check(self, packages: Dict[str, dict]) -> LicenceReport:
        """
        Check a dict of {name: {"version": ..., "licence": ...}} entries.
        """
        findings: List[LicenceFinding] = []
        counts   = {"ALLOWED": 0, "RESTRICTED": 0, "DENIED": 0, "UNKNOWN": 0}

        for name, meta in packages.items():
            version = meta.get("version", "UNKNOWN")
            licence = meta.get("licence", "") or ""
            status, finding = self._classify(name, version, licence)
            counts[status] = counts.get(status, 0) + 1
            if finding:
                findings.append(finding)

        return LicenceReport(
            total_packages = len(packages),
            allowed        = counts["ALLOWED"],
            restricted     = counts["RESTRICTED"],
            denied         = counts["DENIED"],
            unknown        = counts["UNKNOWN"],
            findings       = findings,
            overall_pass   = counts["DENIED"] == 0 and counts["UNKNOWN"] == 0,
        )

    def check_sbom(self, sbom: dict) -> LicenceReport:
        """Check a CycloneDX SBOM dict."""
        packages = {}
        for comp in sbom.get("components", []):
            name    = comp.get("name", "")
            version = comp.get("version", "UNKNOWN")
            lics    = comp.get("licenses", [])
            licence = lics[0].get("license", {}).get("id", "") if lics else ""
            if name:
                packages[name] = {"version": version, "licence": licence}
        return self.check(packages)

    def _classify(
        self, name: str, version: str, licence: str
    ):
        lic_upper = licence.strip().upper()

        # Normalise for comparison
        lic_norm = licence.strip()

        if not lic_norm or lic_upper in {t.upper() for t in _UNKNOWN_TOKENS}:
            return "UNKNOWN", LicenceFinding(
                check_id    = "LC-UNKNOWN",
                severity    = "HIGH",
                package     = name,
                version     = version,
                licence     = licence,
                status      = "UNKNOWN",
                description = f"Package '{name}' has an unknown or unspecified licence. "
                              "Cannot verify compatibility.",
                action      = "Manual review required. Contact package maintainer.",
            )

        if any(lic_norm == d or lic_upper == d.upper() for d in self.denied):
            return "DENIED", LicenceFinding(
                check_id    = "LC-DENIED",
                severity    = "CRITICAL",
                package     = name,
                version     = version,
                licence     = licence,
                status      = "DENIED",
                description = f"Package '{name}' uses licence '{licence}' which is "
                              "incompatible with commercial SaaS deployment.",
                action      = "Remove this package. Find an alternative with a permissive licence.",
            )

        if any(lic_norm == r or lic_upper == r.upper() for r in self.restricted):
            return "RESTRICTED", LicenceFinding(
                check_id    = "LC-RESTRICTED",
                severity    = "MEDIUM",
                package     = name,
                version     = version,
                licence     = licence,
                status      = "RESTRICTED",
                description = f"Package '{name}' uses copyleft licence '{licence}'. "
                              "May require open-sourcing derived works.",
                action      = "Escalate to legal team for review before deployment.",
            )

        return "ALLOWED", None
