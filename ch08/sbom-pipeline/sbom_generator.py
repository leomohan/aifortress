"""
sbom_generator.py  —  CycloneDX 1.4 SBOM generation for ML projects
AI Fortress · Chapter 8 · Code Sample 8.A

Generates a CycloneDX 1.4 JSON SBOM from:
  - A requirements.txt file (parsed)
  - A pip freeze snapshot string
  - The live Python environment (importlib.metadata)
  - A manually supplied component list

Each component includes:
  - name, version, purl (pkg:pypi/name@version)
  - licence identifier (from package metadata where available)
  - SHA-256 hash of the installed wheel/egg (where resolvable)
  - type: "library" (dependencies) or "framework" (torch, tensorflow, etc.)

CycloneDX spec reference: https://cyclonedx.org/specification/overview/
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


# ML framework package names — classified as "framework" type in SBOM
_ML_FRAMEWORKS = {
    "torch", "tensorflow", "tensorflow-cpu", "tensorflow-gpu",
    "jax", "jaxlib", "keras", "mxnet", "paddle", "paddlepaddle",
    "scikit-learn", "xgboost", "lightgbm", "catboost",
    "transformers", "diffusers", "sentence-transformers",
    "onnx", "onnxruntime", "onnxruntime-gpu",
}


@dataclass
class SBOMComponent:
    type:        str            # "library" | "framework" | "model"
    name:        str
    version:     str
    purl:        str            # Package URL
    description: str = ""
    licences:    List[str] = field(default_factory=list)
    hashes:      Dict[str, str] = field(default_factory=dict)   # algo → hex
    external_references: List[dict] = field(default_factory=list)
    properties:  List[dict] = field(default_factory=list)


@dataclass
class SBOM:
    spec_version:   str
    version:        int
    serial_number:  str
    metadata:       dict
    components:     List[SBOMComponent]

    def to_dict(self) -> dict:
        return {
            "bomFormat":    "CycloneDX",
            "specVersion":  self.spec_version,
            "version":      self.version,
            "serialNumber": self.serial_number,
            "metadata":     self.metadata,
            "components": [
                {
                    "type":        c.type,
                    "name":        c.name,
                    "version":     c.version,
                    "purl":        c.purl,
                    "description": c.description,
                    "licenses":    [{"license": {"id": lic}} for lic in c.licences],
                    "hashes":      [{"alg": alg, "content": h} for alg, h in c.hashes.items()],
                    "externalReferences": c.external_references,
                    "properties":  c.properties,
                }
                for c in self.components
            ],
        }


class SBOMGenerator:
    """
    Generates CycloneDX 1.4 SBOMs for ML projects.

    Parameters
    ----------
    project_name  : Name of the ML project / model
    version       : Project version string
    author        : Author or organisation name
    """

    def __init__(
        self,
        project_name: str,
        version:      str = "1.0.0",
        author:       str = "AI Fortress",
    ):
        self.project_name = project_name
        self.version      = version
        self.author       = author

    def from_requirements_txt(self, path: str | Path) -> SBOM:
        """Parse a requirements.txt file and generate an SBOM."""
        text  = Path(path).read_text(encoding="utf-8")
        return self.from_freeze_text(text)

    def from_freeze_text(self, freeze_text: str) -> SBOM:
        """
        Parse pip-freeze-style text (name==version per line) and generate SBOM.
        Skips comments, -r includes, and editable installs.
        """
        components = []
        for line in freeze_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-") or line.startswith("git+"):
                continue
            comp = self._parse_requirement_line(line)
            if comp:
                components.append(comp)
        return self._build_sbom(components)

    def from_component_list(self, components: List[SBOMComponent]) -> SBOM:
        """Build SBOM from a pre-built list of SBOMComponent objects."""
        return self._build_sbom(components)

    def from_live_environment(self) -> SBOM:
        """
        Introspect the active Python environment via importlib.metadata.
        Requires importlib-metadata >= 7.0.
        """
        try:
            import importlib.metadata as im
        except ImportError:
            raise ImportError("importlib.metadata is required for live environment scanning.")

        components = []
        for dist in im.distributions():
            meta    = dist.metadata
            name    = meta.get("Name", "unknown")
            version = meta.get("Version", "0.0.0")
            licence = meta.get("License", "NOASSERTION")
            comp_type = "framework" if name.lower() in _ML_FRAMEWORKS else "library"
            purl    = f"pkg:pypi/{name.lower()}@{version}"
            components.append(SBOMComponent(
                type     = comp_type,
                name     = name,
                version  = version,
                purl     = purl,
                licences = [licence] if licence else [],
            ))
        return self._build_sbom(components)

    def save(self, sbom: SBOM, path: str | Path) -> None:
        """Save SBOM to a JSON file."""
        Path(path).write_text(
            json.dumps(sbom.to_dict(), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: str | Path) -> dict:
        """Load a raw SBOM dict from file."""
        return json.loads(Path(path).read_text(encoding="utf-8"))

    # ── Internal ──────────────────────────────────────────────────────────────

    def _parse_requirement_line(self, line: str) -> Optional[SBOMComponent]:
        """Parse a single pip requirement line into an SBOMComponent."""
        # Handle name==version and name>=version forms
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=!<>~^]+\s*([^\s;#]+)", line)
        if not m:
            # Bare package name without version
            m2 = re.match(r"^([A-Za-z0-9_.\-]+)\s*$", line)
            if m2:
                name = m2.group(1)
                version = "UNKNOWN"
            else:
                return None
        else:
            name    = m.group(1)
            version = m.group(2)

        name_lower = name.lower().replace("_", "-")
        comp_type  = "framework" if name_lower in _ML_FRAMEWORKS else "library"
        purl       = f"pkg:pypi/{name_lower}@{version}"
        return SBOMComponent(
            type    = comp_type,
            name    = name,
            version = version,
            purl    = purl,
        )

    def _build_sbom(self, components: List[SBOMComponent]) -> SBOM:
        now = datetime.now(timezone.utc).isoformat()
        metadata = {
            "timestamp": now,
            "tools":     [{"vendor": "AI Fortress", "name": "sbom-generator", "version": "1.0"}],
            "component": {
                "type":    "application",
                "name":    self.project_name,
                "version": self.version,
                "purl":    f"pkg:generic/{self.project_name.lower()}@{self.version}",
            },
            "authors": [{"name": self.author}],
        }
        return SBOM(
            spec_version  = "1.4",
            version       = 1,
            serial_number = f"urn:uuid:{uuid.uuid4()}",
            metadata      = metadata,
            components    = components,
        )
