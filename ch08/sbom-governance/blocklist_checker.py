"""
blocklist_checker.py  —  Known-bad component blocklist for SBOM governance
AI Fortress · Chapter 8 · Code Sample 8.E

Checks all SBOM components against a blocklist of:
  - Known malicious packages (typosquats, supply-chain-attack packages)
  - Internally prohibited packages (deprecated, security-rejected)
  - Packages with critical unpatched CVEs awaiting internal assessment

Blocklist entry format:
  {
    "numpy-base": {
      "reason": "Known typosquat of numpy — installs keylogger",
      "severity": "CRITICAL",
      "cve": "",
      "added": "2024-01-15",
      "reference": "https://advisory.example.com/numpy-base"
    }
  }

Matching is case-insensitive and normalises underscores to hyphens.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# Built-in blocklist of well-known malicious ML ecosystem packages
# (illustrative — keep this updated from threat intel feeds in production)
_DEFAULT_BLOCKLIST: Dict[str, dict] = {
    "numpy-base":          {"reason": "Typosquat of numpy — executes malicious install script",
                             "severity": "CRITICAL", "cve": "", "added": "2024-01-10"},
    "torch-nightly-cpu":   {"reason": "Dependency confusion attack vector on private registry",
                             "severity": "CRITICAL", "cve": "", "added": "2024-02-01"},
    "sklearn":             {"reason": "Typosquat of scikit-learn — install-time code execution",
                             "severity": "CRITICAL", "cve": "", "added": "2023-11-20"},
    "transformers-base":   {"reason": "Malicious package — exfiltrates HuggingFace tokens",
                             "severity": "CRITICAL", "cve": "", "added": "2024-03-05"},
    "python-jwt":          {"reason": "Known critical JWT bypass CVE — use PyJWT instead",
                             "severity": "HIGH",     "cve": "CVE-2022-39227", "added": "2022-10-01"},
    "pillow":              {"reason": "Versions < 9.3.0 have critical RCE — ensure patched",
                             "severity": "HIGH",     "cve": "CVE-2022-45199", "added": "2022-11-15",
                             "version_below": "9.3.0"},
}


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


@dataclass
class BlocklistHit:
    component:   str
    version:     str
    severity:    str
    reason:      str
    cve:         str
    reference:   str
    added:       str


@dataclass
class BlocklistReport:
    total_components: int
    hits:            List[BlocklistHit]
    overall_pass:    bool

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} Blocklist check: {len(self.hits)} hit(s) "
            f"across {self.total_components} components."
        )


class BlocklistViolationError(RuntimeError):
    """Raised when blocklisted components are present in the SBOM."""
    def __init__(self, hits: List[BlocklistHit]):
        names = [h.component for h in hits]
        super().__init__(
            f"Blocklist check FAILED: {len(hits)} prohibited component(s) found: {names}"
        )
        self.hits = hits


class BlocklistChecker:
    """
    Checks SBOM components against a known-bad package blocklist.

    Parameters
    ----------
    blocklist : Dict of {package_name: metadata_dict}.
                Defaults to the built-in ML supply chain threat blocklist.
    """

    def __init__(self, blocklist: Optional[Dict[str, dict]] = None):
        raw = blocklist if blocklist is not None else _DEFAULT_BLOCKLIST
        # Normalise all keys
        self._bl: Dict[str, dict] = {_normalise(k): v for k, v in raw.items()}

    def check(self, sbom: dict) -> BlocklistReport:
        """Check a CycloneDX SBOM dict against the blocklist."""
        components = sbom.get("components", [])
        hits: List[BlocklistHit] = []

        for comp in components:
            name    = comp.get("name", "")
            version = comp.get("version", "")
            norm    = _normalise(name)

            if norm not in self._bl:
                continue

            entry = self._bl[norm]

            # Version-range check: if 'version_below' key present, only flag versions below it
            if "version_below" in entry and version:
                try:
                    from cve_scanner import _parse_version, _version_in_range  # local import
                    if not _version_in_range(version, "0", entry["version_below"]):
                        continue   # version is patched
                except Exception:
                    pass   # conservative: flag anyway if version parse fails

            hits.append(BlocklistHit(
                component = name,
                version   = version,
                severity  = entry.get("severity", "HIGH"),
                reason    = entry.get("reason", ""),
                cve       = entry.get("cve", ""),
                reference = entry.get("reference", ""),
                added     = entry.get("added", ""),
            ))

        return BlocklistReport(
            total_components = len(components),
            hits             = hits,
            overall_pass     = len(hits) == 0,
        )

    def enforce(self, sbom: dict) -> BlocklistReport:
        """Run check() and raise BlocklistViolationError on any hit."""
        report = self.check(sbom)
        if not report.overall_pass:
            raise BlocklistViolationError(report.hits)
        return report

    def load_blocklist_file(self, path: str | Path) -> None:
        """Merge an additional blocklist JSON file into the current blocklist."""
        extra = json.loads(Path(path).read_text(encoding="utf-8"))
        for k, v in extra.items():
            self._bl[_normalise(k)] = v
