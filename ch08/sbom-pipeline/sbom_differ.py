"""
sbom_differ.py  —  SBOM snapshot comparison and drift detection
AI Fortress · Chapter 8 · Code Sample 8.A

Compares two CycloneDX SBOM JSON files or dicts and reports:
  - Added components   (new packages not in baseline)
  - Removed components (packages dropped since baseline)
  - Version changes    (same package, different version)
  - Licence changes    (licence identifier changed)

Optionally enforces an approved-component allowlist:
  raises SBOMDriftError if any added component is not in the allowlist.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class ComponentChange:
    change_type:  str       # "added" | "removed" | "version_changed" | "licence_changed"
    name:         str
    old_value:    str = ""  # old version or licence
    new_value:    str = ""  # new version or licence
    severity:     str = "INFO"   # "INFO" | "WARNING" | "CRITICAL"
    purl:         str = ""


@dataclass
class SBOMDiff:
    added:           List[ComponentChange]
    removed:         List[ComponentChange]
    version_changes: List[ComponentChange]
    licence_changes: List[ComponentChange]
    total_changes:   int
    drift_detected:  bool
    unapproved:      List[str]   # component names not in approved list

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        if not self.drift_detected:
            return "✅ No SBOM drift detected."
        parts = []
        if self.added:           parts.append(f"{len(self.added)} added")
        if self.removed:         parts.append(f"{len(self.removed)} removed")
        if self.version_changes: parts.append(f"{len(self.version_changes)} version changes")
        if self.licence_changes: parts.append(f"{len(self.licence_changes)} licence changes")
        unapproved = f" | ⛔ {len(self.unapproved)} unapproved" if self.unapproved else ""
        return f"⚠️  SBOM drift: {', '.join(parts)}{unapproved}"


class SBOMDriftError(RuntimeError):
    """Raised when added components are not in the approved allowlist."""
    def __init__(self, unapproved: List[str]):
        super().__init__(
            f"SBOM drift blocked: {len(unapproved)} unapproved component(s) added: "
            + ", ".join(unapproved)
        )
        self.unapproved = unapproved


class SBOMDiffer:
    """
    Compares two CycloneDX SBOM snapshots.

    Parameters
    ----------
    approved_components : Optional set of package names that are pre-approved.
                          If set, any added component not in this set triggers
                          SBOMDriftError when enforce() is called.
    """

    def __init__(self, approved_components: Optional[Set[str]] = None):
        self.approved = approved_components

    def diff(self, baseline: dict, current: dict) -> SBOMDiff:
        """
        Compare baseline SBOM dict against current SBOM dict.
        Both must be CycloneDX JSON dicts (from SBOMGenerator.load() or .to_dict()).
        """
        baseline_map = self._index(baseline)
        current_map  = self._index(current)

        added:           List[ComponentChange] = []
        removed:         List[ComponentChange] = []
        version_changes: List[ComponentChange] = []
        licence_changes: List[ComponentChange] = []

        # Added
        for name, comp in current_map.items():
            if name not in baseline_map:
                added.append(ComponentChange(
                    change_type = "added",
                    name        = name,
                    new_value   = comp["version"],
                    purl        = comp.get("purl", ""),
                    severity    = "WARNING",
                ))

        # Removed
        for name, comp in baseline_map.items():
            if name not in current_map:
                removed.append(ComponentChange(
                    change_type = "removed",
                    name        = name,
                    old_value   = comp["version"],
                    purl        = comp.get("purl", ""),
                    severity    = "INFO",
                ))

        # Changed
        for name in set(baseline_map) & set(current_map):
            old = baseline_map[name]
            new = current_map[name]
            if old["version"] != new["version"]:
                version_changes.append(ComponentChange(
                    change_type = "version_changed",
                    name        = name,
                    old_value   = old["version"],
                    new_value   = new["version"],
                    purl        = new.get("purl", ""),
                    severity    = "INFO",
                ))
            old_lic = ",".join(sorted(old.get("licences", [])))
            new_lic = ",".join(sorted(new.get("licences", [])))
            if old_lic != new_lic:
                licence_changes.append(ComponentChange(
                    change_type = "licence_changed",
                    name        = name,
                    old_value   = old_lic,
                    new_value   = new_lic,
                    purl        = new.get("purl", ""),
                    severity    = "WARNING",
                ))

        all_changes  = added + removed + version_changes + licence_changes
        unapproved   = []
        if self.approved is not None:
            unapproved = [c.name for c in added if c.name.lower() not in self.approved]

        return SBOMDiff(
            added           = added,
            removed         = removed,
            version_changes = version_changes,
            licence_changes = licence_changes,
            total_changes   = len(all_changes),
            drift_detected  = len(all_changes) > 0,
            unapproved      = unapproved,
        )

    def diff_files(self, baseline_path: str | Path, current_path: str | Path) -> SBOMDiff:
        baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        current  = json.loads(Path(current_path).read_text(encoding="utf-8"))
        return self.diff(baseline, current)

    def enforce(self, diff: SBOMDiff) -> None:
        """Raise SBOMDriftError if any unapproved components were added."""
        if diff.unapproved:
            raise SBOMDriftError(diff.unapproved)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _index(sbom: dict) -> Dict[str, dict]:
        """Build a name → {version, purl, licences} index from an SBOM dict."""
        result = {}
        for comp in sbom.get("components", []):
            name     = comp.get("name", "").lower()
            version  = comp.get("version", "UNKNOWN")
            purl     = comp.get("purl", "")
            licences = [
                lic.get("license", {}).get("id", "")
                for lic in comp.get("licenses", [])
            ]
            if name:
                result[name] = {"version": version, "purl": purl, "licences": licences}
        return result
