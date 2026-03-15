"""
sbom_registry.py  —  SBOM snapshot registry for governance tracking
AI Fortress · Chapter 8 · Code Sample 8.E

A local SBOM registry that:
  - Stores CycloneDX SBOM snapshots per project and version
  - Supports baseline comparison for drift detection (delegates to SBOMDiffer)
  - Provides a query interface (latest, by-version, list all)
  - Records governance metadata (approved-by, approval-date, gate results)

Storage: a single JSON index file + individual SBOM JSON files in a directory.

Registry structure on disk:
  registry/
    index.json              ← project→version→metadata index
    sboms/
      <project>__<version>__<timestamp>.json
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class RegistryEntry:
    project:       str
    version:       str
    sbom_file:     str          # filename within registry/sboms/
    registered_at: str
    serial_number: str
    component_count: int
    approved_by:   str = ""
    approved_at:   str = ""
    gate_results:  Dict[str, bool] = field(default_factory=dict)


class SBOMRegistry:
    """
    Persistent SBOM snapshot registry.

    Parameters
    ----------
    registry_dir : Path to the registry root directory.
                   Created on first use if it does not exist.
    """

    def __init__(self, registry_dir: str | Path):
        self.root  = Path(registry_dir)
        self.sboms = self.root / "sboms"
        self.index_path = self.root / "index.json"
        self._index: Dict[str, Dict[str, RegistryEntry]] = {}
        self._load_index()

    # ── Write ─────────────────────────────────────────────────────────────────

    def register(
        self,
        sbom:        dict,
        approved_by: str = "",
        gate_results: Optional[Dict[str, bool]] = None,
    ) -> RegistryEntry:
        """
        Register an SBOM snapshot.  Returns the new RegistryEntry.
        Overwrites any existing entry for the same project+version.
        """
        meta        = sbom.get("metadata", {})
        comp_meta   = meta.get("component", {}) or {}
        project     = comp_meta.get("name", sbom.get("serialNumber", "unknown"))
        version     = comp_meta.get("version", "UNKNOWN")
        serial      = sbom.get("serialNumber", str(uuid.uuid4()))
        n_comps     = len(sbom.get("components", []))
        now         = datetime.now(timezone.utc).isoformat()

        safe_proj   = re.sub(r"[^\w\-.]", "_", project)
        safe_ver    = re.sub(r"[^\w\-.]", "_", version)
        filename    = f"{safe_proj}__{safe_ver}__{now[:19].replace(':', '-')}.json"

        self.sboms.mkdir(parents=True, exist_ok=True)
        (self.sboms / filename).write_text(
            json.dumps(sbom, indent=2), encoding="utf-8"
        )

        entry = RegistryEntry(
            project        = project,
            version        = version,
            sbom_file      = filename,
            registered_at  = now,
            serial_number  = serial,
            component_count = n_comps,
            approved_by    = approved_by,
            approved_at    = now if approved_by else "",
            gate_results   = gate_results or {},
        )
        self._index.setdefault(project, {})[version] = entry
        self._save_index()
        return entry

    def approve(self, project: str, version: str, approved_by: str) -> None:
        """Record approval for a registered SBOM."""
        entry = self._get_entry(project, version)
        entry.approved_by = approved_by
        entry.approved_at = datetime.now(timezone.utc).isoformat()
        self._save_index()

    def record_gate_result(self, project: str, version: str, gate: str, passed: bool) -> None:
        """Record the result of a governance gate for a registered SBOM."""
        entry = self._get_entry(project, version)
        entry.gate_results[gate] = passed
        self._save_index()

    # ── Read ──────────────────────────────────────────────────────────────────

    def get(self, project: str, version: str) -> dict:
        """Load and return the SBOM dict for the given project + version."""
        entry = self._get_entry(project, version)
        return json.loads((self.sboms / entry.sbom_file).read_text(encoding="utf-8"))

    def latest(self, project: str) -> Optional[dict]:
        """Return the SBOM dict for the most recently registered version."""
        versions = self._index.get(project, {})
        if not versions:
            return None
        latest_ver = max(versions.values(), key=lambda e: e.registered_at)
        return self.get(project, latest_ver.version)

    def list_projects(self) -> List[str]:
        return sorted(self._index.keys())

    def list_versions(self, project: str) -> List[str]:
        return sorted(self._index.get(project, {}).keys())

    def get_entry(self, project: str, version: str) -> Optional[RegistryEntry]:
        return self._index.get(project, {}).get(version)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_entry(self, project: str, version: str) -> RegistryEntry:
        entry = self._index.get(project, {}).get(version)
        if entry is None:
            raise KeyError(f"SBOM not found: project='{project}' version='{version}'")
        return entry

    def _load_index(self) -> None:
        if self.index_path.exists():
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
            for proj, versions in raw.items():
                self._index[proj] = {
                    ver: RegistryEntry(**entry_dict)
                    for ver, entry_dict in versions.items()
                }

    def _save_index(self) -> None:
        import dataclasses
        self.root.mkdir(parents=True, exist_ok=True)
        serialisable = {
            proj: {ver: dataclasses.asdict(entry) for ver, entry in versions.items()}
            for proj, versions in self._index.items()
        }
        self.index_path.write_text(json.dumps(serialisable, indent=2), encoding="utf-8")
