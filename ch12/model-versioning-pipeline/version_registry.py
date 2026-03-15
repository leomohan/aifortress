"""
version_registry.py  —  Semantic version registry for ML models
AI Fortress · Chapter 12 · Code Sample 12.A

Enforces SemVer (MAJOR.MINOR.PATCH[-pre-release]) discipline on model
versions. Prevents downgrade registrations and maintains a full history
of all versions registered per model name.

Version comparison rules:
  - MAJOR.MINOR.PATCH compared numerically
  - Pre-release versions (e.g. 2.1.0-rc.1) are LESS THAN their release
  - A new registration must have a strictly higher version than the latest
    registered version for that model (no downgrades, no duplicates)
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


_SEMVER_RE = re.compile(
    r"^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[a-zA-Z0-9._-]+))?$"
)


@dataclass
class ModelVersion:
    model_name:   str
    version:      str
    registered_by: str
    registered_at: str
    description:  str = ""
    tags:         List[str] = field(default_factory=list)
    artefact_hash: str = ""        # SHA-256 of model artefact, if linked
    version_id:   str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class VersionHistory:
    model_name: str
    versions:   List[ModelVersion]   # ordered oldest → newest

    @property
    def latest(self) -> Optional[ModelVersion]:
        return self.versions[-1] if self.versions else None


def parse_semver(version: str) -> Tuple[int, int, int, str]:
    """Parse a SemVer string. Returns (major, minor, patch, pre_release)."""
    m = _SEMVER_RE.match(version)
    if not m:
        raise ValueError(
            f"Invalid SemVer '{version}'. Expected MAJOR.MINOR.PATCH[-pre-release]."
        )
    return (
        int(m.group("major")),
        int(m.group("minor")),
        int(m.group("patch")),
        m.group("pre") or "",
    )


def compare_semver(a: str, b: str) -> int:
    """
    Compare two SemVer strings.
    Returns -1 if a < b, 0 if equal, 1 if a > b.
    Pre-release versions rank below their release (2.0.0-rc < 2.0.0).
    """
    ma, mia, pa, prea = parse_semver(a)
    mb, mib, pb, preb = parse_semver(b)

    for va, vb in [(ma, mb), (mia, mib), (pa, pb)]:
        if va < vb:
            return -1
        if va > vb:
            return 1

    # Equal numeric parts: compare pre-release
    if prea == preb:
        return 0
    if prea and not preb:
        return -1   # pre-release < release
    if not prea and preb:
        return 1
    # Both have pre-release: lexicographic
    return (-1 if prea < preb else 1)


class VersionRegistry:
    """
    Manages semantic version registration for ML models.

    Parameters
    ----------
    audit_path : Optional JSON Lines path for registration events.
    """

    def __init__(self, audit_path: Optional[str | Path] = None):
        self._history: Dict[str, List[ModelVersion]] = {}
        self._audit   = Path(audit_path) if audit_path else None

    def register(
        self,
        model_name:    str,
        version:       str,
        registered_by: str,
        description:   str = "",
        tags:          Optional[List[str]] = None,
        artefact_hash: str = "",
    ) -> ModelVersion:
        """
        Register a new version for a model.
        Raises ValueError if version is invalid, duplicate, or a downgrade.
        """
        parse_semver(version)   # validate format

        existing = self._history.get(model_name, [])
        for v in existing:
            if v.version == version:
                raise ValueError(
                    f"Version '{version}' is already registered for '{model_name}'."
                )
        if existing:
            latest = existing[-1].version
            if compare_semver(version, latest) <= 0:
                raise ValueError(
                    f"Version '{version}' is not greater than current latest "
                    f"'{latest}' for model '{model_name}'. Downgrades are not permitted."
                )

        mv = ModelVersion(
            model_name    = model_name,
            version       = version,
            registered_by = registered_by,
            registered_at = datetime.now(timezone.utc).isoformat(),
            description   = description,
            tags          = tags or [],
            artefact_hash = artefact_hash,
        )
        self._history.setdefault(model_name, []).append(mv)
        self._log("version_registered", model=model_name, version=version,
                  registered_by=registered_by)
        return mv

    def get_history(self, model_name: str) -> VersionHistory:
        return VersionHistory(
            model_name=model_name,
            versions=list(self._history.get(model_name, [])),
        )

    def get_latest(self, model_name: str) -> Optional[ModelVersion]:
        versions = self._history.get(model_name, [])
        return versions[-1] if versions else None

    def get_version(self, model_name: str, version: str) -> Optional[ModelVersion]:
        for v in self._history.get(model_name, []):
            if v.version == version:
                return v
        return None

    def list_models(self) -> List[str]:
        return sorted(self._history.keys())

    def _log(self, event: str, **kwargs) -> None:
        if not self._audit:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, **kwargs}
        with open(self._audit, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
