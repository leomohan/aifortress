"""
transitive_risk_scorer.py  —  Dependency graph risk propagation
AI Fortress · Chapter 8 · Code Sample 8.B

Builds a dependency graph and propagates CVE risk scores from vulnerable
leaf packages upward to their dependents. Computes a composite risk score
per package accounting for:
  - Direct CVSS score (from CVE scanner)
  - Transitive exposure depth (how many hops away from a vulnerability)
  - Breadth of dependents (how many packages depend on a vulnerable package)

Graph input format:
  {
    "numpy": ["python"],
    "torch": ["numpy", "python"],
    "transformers": ["torch", "numpy", "requests"],
    ...
  }
  (each entry: package → list of its direct dependencies)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class TransitiveRiskEntry:
    package:          str
    direct_cve_score: float       # highest CVE score of direct vulnerabilities
    transitive_score: float       # propagated score from dependencies
    composite_score:  float       # weighted combination
    risk_level:       str         # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE"
    vulnerable_deps:  List[str]   # which of its dependencies have CVEs
    depth:            int         # shortest path length to a vulnerable package (0 = direct)


@dataclass
class TransitiveRiskReport:
    entries:         List[TransitiveRiskEntry]
    high_risk_count: int
    total_packages:  int

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    def top_risk(self, n: int = 10) -> List[TransitiveRiskEntry]:
        return sorted(self.entries, key=lambda e: e.composite_score, reverse=True)[:n]


class TransitiveRiskScorer:
    """
    Scores packages by their total risk exposure including transitive dependencies.

    Parameters
    ----------
    decay_factor : Score decay per hop (0 < decay < 1); default 0.5 means
                   a score of 9.0 two hops away contributes 9.0 × 0.5² = 2.25
    """

    def __init__(self, decay_factor: float = 0.5):
        self.decay = decay_factor

    def score(
        self,
        graph:      Dict[str, List[str]],       # package → direct deps
        cve_scores: Dict[str, float],            # package → highest CVE CVSS score
    ) -> TransitiveRiskReport:
        """
        Compute transitive risk for all packages in the dependency graph.

        Parameters
        ----------
        graph      : Adjacency list: package → its direct dependencies
        cve_scores : Dict of package name → highest applicable CVSS score
        """
        all_packages = set(graph.keys())
        # Add packages that only appear as dependencies
        for deps in graph.values():
            all_packages.update(deps)

        entries: List[TransitiveRiskEntry] = []

        for pkg in sorted(all_packages):
            direct_score = cve_scores.get(pkg, 0.0)

            # BFS to find vulnerable transitive dependencies and their depths
            visited:       Set[str]         = {pkg}
            queue:         List[Tuple[str, int]] = [(d, 1) for d in graph.get(pkg, [])]
            vuln_deps:     List[Tuple[str, int]] = []   # (dep, depth)

            while queue:
                dep, depth = queue.pop(0)
                if dep in visited:
                    continue
                visited.add(dep)
                if cve_scores.get(dep, 0.0) > 0:
                    vuln_deps.append((dep, depth))
                for sub_dep in graph.get(dep, []):
                    if sub_dep not in visited:
                        queue.append((sub_dep, depth + 1))

            # Transitive score: sum of decayed CVE scores from vulnerable deps
            transitive_score = sum(
                cve_scores[d] * (self.decay ** depth)
                for d, depth in vuln_deps
            )
            transitive_score = min(10.0, round(transitive_score, 2))

            # Composite: 70% direct + 30% transitive
            composite = round(0.7 * direct_score + 0.3 * transitive_score, 2)

            min_depth = min((depth for _, depth in vuln_deps), default=0) if vuln_deps else (0 if direct_score > 0 else 999)

            entries.append(TransitiveRiskEntry(
                package          = pkg,
                direct_cve_score = direct_score,
                transitive_score = transitive_score,
                composite_score  = composite,
                risk_level       = self._level(composite),
                vulnerable_deps  = [d for d, _ in vuln_deps],
                depth            = min_depth if (vuln_deps or direct_score > 0) else 999,
            ))

        high_risk = sum(1 for e in entries if e.risk_level in ("CRITICAL", "HIGH"))
        return TransitiveRiskReport(
            entries          = entries,
            high_risk_count  = high_risk,
            total_packages   = len(entries),
        )

    @staticmethod
    def _level(score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score >  0.0: return "LOW"
        return "NONE"
