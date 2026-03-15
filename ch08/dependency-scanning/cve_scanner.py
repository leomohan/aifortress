"""
cve_scanner.py  —  CVE matching and CVSS scoring for ML dependencies
AI Fortress · Chapter 8 · Code Sample 8.B

Matches installed packages against a CVE database and scores findings.

CVE database format (subset of NIST NVD JSON feed):
  {
    "CVE-2024-XXXX": {
      "description": "...",
      "cvss_v3_score": 9.8,
      "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "affected": [
        {"package": "numpy", "version_start": "1.0.0", "version_end": "1.24.3"}
      ],
      "fix_version": "1.24.4",
      "published": "2024-01-15"
    }
  }

ML-context severity multiplier:
  Training packages (torch, tensorflow, scikit-learn, etc.) get ×1.5 multiplier
  because a compromised training environment can poison the model itself.
  Inference-only serving packages get ×1.0 baseline.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Packages used at training time — higher risk multiplier
_TRAINING_PACKAGES = {
    "torch", "tensorflow", "jax", "jaxlib", "keras",
    "scikit-learn", "xgboost", "lightgbm", "catboost",
    "transformers", "datasets", "accelerate", "peft",
    "wandb", "mlflow", "optuna", "ray",
}


def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    parts = []
    for p in v.split(".")[:4]:
        try:
            parts.append(int("".join(c for c in p if c.isdigit()) or "0"))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _version_in_range(version: str, start: str, end: str) -> bool:
    """Return True if start <= version < end (inclusive start, exclusive end)."""
    try:
        v     = _parse_version(version)
        v_s   = _parse_version(start) if start else (0,)
        v_e   = _parse_version(end)   if end   else (999999,)
        return v_s <= v < v_e
    except Exception:
        return False


@dataclass
class CVEFinding:
    cve_id:          str
    package:         str
    installed_version: str
    cvss_v3_score:   float
    adjusted_score:  float      # after ML-context multiplier
    severity:        str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    description:     str
    fix_version:     str
    published:       str
    training_context: bool      # True if package used during training


@dataclass
class CVEScanReport:
    total_packages:  int
    vulnerable:      int
    critical:        int
    high:            int
    medium:          int
    low:             int
    findings:        List[CVEFinding]
    overall_pass:    bool       # True if no CRITICAL or HIGH findings

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return (
            f"{icon} CVE Scan: {self.vulnerable}/{self.total_packages} packages vulnerable. "
            f"{self.critical}C {self.high}H {self.medium}M {self.low}L"
        )


class CVEScanner:
    """
    Scans a package list against a CVE database.

    Parameters
    ----------
    cve_db        : CVE database dict (NVD-subset format) or path to JSON file
    fail_on_score : CVSS adjusted score threshold above which scan fails (default 7.0)
    """

    def __init__(
        self,
        cve_db:        dict | str | Path,
        fail_on_score: float = 7.0,
    ):
        if isinstance(cve_db, (str, Path)):
            cve_db = json.loads(Path(cve_db).read_text(encoding="utf-8"))
        self.db            = cve_db
        self.fail_on_score = fail_on_score

    def scan(self, packages: Dict[str, str]) -> CVEScanReport:
        """
        Scan a dict of {package_name: version} against the CVE database.
        """
        findings: List[CVEFinding] = []

        for cve_id, cve in self.db.items():
            for affected in cve.get("affected", []):
                pkg_name = affected.get("package", "").lower()
                v_start  = affected.get("version_start", "0.0.0")
                v_end    = affected.get("version_end", "")

                # Find installed version
                installed = None
                for name, ver in packages.items():
                    if name.lower().replace("_", "-") == pkg_name.replace("_", "-"):
                        installed = (name, ver)
                        break

                if installed is None:
                    continue
                pkg, version = installed

                if not _version_in_range(version, v_start, v_end):
                    continue

                # Apply ML-context multiplier
                base_score    = float(cve.get("cvss_v3_score", 0.0))
                is_training   = pkg.lower() in _TRAINING_PACKAGES
                multiplier    = 1.5 if is_training else 1.0
                adj_score     = min(10.0, round(base_score * multiplier, 1))
                severity      = self._severity(adj_score)

                findings.append(CVEFinding(
                    cve_id            = cve_id,
                    package           = pkg,
                    installed_version = version,
                    cvss_v3_score     = base_score,
                    adjusted_score    = adj_score,
                    severity          = severity,
                    description       = cve.get("description", ""),
                    fix_version       = cve.get("fix_version", ""),
                    published         = cve.get("published", ""),
                    training_context  = is_training,
                ))

        counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return CVEScanReport(
            total_packages = len(packages),
            vulnerable     = len({f.package for f in findings}),
            critical       = counts["CRITICAL"],
            high           = counts["HIGH"],
            medium         = counts["MEDIUM"],
            low            = counts["LOW"],
            findings       = findings,
            overall_pass   = counts["CRITICAL"] == 0 and counts["HIGH"] == 0,
        )

    def scan_freeze(self, freeze_text: str) -> CVEScanReport:
        """Parse pip-freeze text and scan."""
        import re
        packages = {}
        for line in freeze_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)==([^\s;#]+)", line)
            if m:
                packages[m.group(1)] = m.group(2)
        return self.scan(packages)

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        return "LOW"
