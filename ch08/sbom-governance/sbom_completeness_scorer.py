"""
sbom_completeness_scorer.py  —  CycloneDX SBOM completeness scoring
AI Fortress · Chapter 8 · Code Sample 8.E

Scores a CycloneDX SBOM against the AI Fortress completeness standard.

Completeness dimensions scored:
  1. Metadata completeness (timestamp, tool, author, component identity)
  2. Component coverage (% of components with required fields)
  3. PURL coverage (% of components with a package URL)
  4. Version coverage (% of components with explicit versions)
  5. Licence coverage (% of components with licence info)
  6. Hash coverage (% of components with at least one hash)
  7. Type correctness (all components have a valid CycloneDX type)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


_VALID_TYPES = {
    "application", "container", "device", "file",
    "firmware", "framework", "library", "machine-learning-model",
    "data", "platform",
}


@dataclass
class CompletenessScore:
    project_name:    str
    total_score:     float          # 0–100
    dimension_scores: Dict[str, float]
    total_components: int
    issues:          List[str]
    overall_pass:    bool

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def summary(self) -> str:
        icon = "✅" if self.overall_pass else "❌"
        return f"{icon} SBOM completeness '{self.project_name}': {self.total_score:.0f}/100"


class SBOMCompletenessScorer:
    """
    Scores CycloneDX SBOM completeness.

    Parameters
    ----------
    pass_threshold : Minimum score to pass (default 75)
    """

    def __init__(self, pass_threshold: float = 75.0):
        self.threshold = pass_threshold

    def score(self, sbom: dict) -> CompletenessScore:
        components = sbom.get("components", [])
        n          = len(components)
        issues: List[str] = []

        # 1. Metadata (20 points)
        meta       = sbom.get("metadata", {})
        meta_score = 0.0
        if meta.get("timestamp"):  meta_score += 5
        else: issues.append("metadata.timestamp missing")
        if meta.get("tools"):      meta_score += 5
        else: issues.append("metadata.tools missing")
        if meta.get("authors"):    meta_score += 5
        else: issues.append("metadata.authors missing")
        if meta.get("component"):  meta_score += 5
        else: issues.append("metadata.component (subject) missing")

        if n == 0:
            return CompletenessScore(
                project_name     = meta.get("component", {}).get("name", "unknown"),
                total_score      = meta_score,
                dimension_scores = {"metadata": meta_score},
                total_components = 0,
                issues           = issues + ["No components found in SBOM"],
                overall_pass     = False,
            )

        # 2–7: component-level coverage (each = 80/6 ≈ 13.3 pts)
        def pct(count): return 100.0 * count / n

        purl_count    = sum(1 for c in components if c.get("purl"))
        version_count = sum(1 for c in components if c.get("version") and c["version"] != "UNKNOWN")
        licence_count = sum(1 for c in components if c.get("licenses"))
        hash_count    = sum(1 for c in components if c.get("hashes"))
        type_ok_count = sum(1 for c in components if c.get("type", "") in _VALID_TYPES)
        name_count    = sum(1 for c in components if c.get("name"))

        if pct(purl_count) < 80:    issues.append(f"Only {purl_count}/{n} components have PURLs")
        if pct(version_count) < 80: issues.append(f"Only {version_count}/{n} components have explicit versions")
        if pct(licence_count) < 60: issues.append(f"Only {licence_count}/{n} components have licence info")
        if pct(type_ok_count) < 90: issues.append(f"Only {type_ok_count}/{n} components have valid CycloneDX types")

        dim = {
            "metadata":  round(meta_score, 1),
            "purl":      round(pct(purl_count)    * 0.133, 1),
            "version":   round(pct(version_count) * 0.133, 1),
            "licence":   round(pct(licence_count) * 0.133, 1),
            "hash":      round(pct(hash_count)    * 0.133, 1),
            "type":      round(pct(type_ok_count) * 0.133, 1),
            "name":      round(pct(name_count)    * 0.133, 1),
        }
        total = min(100.0, round(meta_score + sum(v for k, v in dim.items() if k != "metadata"), 1))

        project = meta.get("component", {}).get("name", sbom.get("serialNumber", "unknown"))
        return CompletenessScore(
            project_name      = project,
            total_score       = total,
            dimension_scores  = dim,
            total_components  = n,
            issues            = issues,
            overall_pass      = total >= self.threshold and len(issues) == 0,
        )

    def score_file(self, path: str | Path) -> CompletenessScore:
        return self.score(json.loads(Path(path).read_text(encoding="utf-8")))
