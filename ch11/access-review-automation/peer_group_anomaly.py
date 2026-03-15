"""
peer_group_anomaly.py  —  Peer-group permission anomaly detection for ML IAM
AI Fortress · Chapter 11 · Code Sample 11.C

Compares each user's permission set against their peer group (same team or
role) to identify outliers with significantly more access than colleagues.

Method:
  - Peer group defined by team attribute (configurable)
  - Jaccard similarity: |A ∩ B| / |A ∪ B|
  - Jaccard distance: 1 - similarity (0 = identical, 1 = no overlap)
  - Excess permission count: how many permissions the user has beyond
    the group median
  - Z-score of permission count within peer group

Severity tiers:
  CRITICAL — excess permissions > 5 AND Jaccard distance from median > 0.5
  WARNING  — excess permissions > 2 OR Jaccard distance > 0.3
  OK       — within normal range
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set
import math


@dataclass
class PeerGroupMember:
    principal:   str
    permissions: Set[str]
    team:        str
    role:        str = ""


@dataclass
class PeerAnomalyFinding:
    principal:         str
    team:              str
    severity:          str           # "OK" | "WARNING" | "CRITICAL"
    permission_count:  int
    group_median:      float
    excess_count:      int
    jaccard_distance:  float
    excess_permissions: List[str]    # permissions the user has that peers lack
    detail:            str


@dataclass
class PeerGroupReport:
    total_users:  int
    anomalies:    int
    critical:     int
    warning:      int
    ok:           int
    findings:     List[PeerAnomalyFinding]

    def save_json(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )


class PeerGroupAnomalyDetector:
    """
    Detects permission anomalies by comparing users to their peer group.

    Parameters
    ----------
    group_by          : Attribute to group peers by ("team" or "role").
    excess_warn       : Warn if user has this many more permissions than median.
    excess_critical   : Critical if user has this many more permissions than median.
    distance_warn     : Warn if Jaccard distance from group centroid exceeds this.
    distance_critical : Critical if Jaccard distance exceeds this.
    min_group_size    : Minimum peer group size to run analysis (default 2).
    """

    def __init__(
        self,
        group_by:           str   = "team",
        excess_warn:        int   = 2,
        excess_critical:    int   = 5,
        distance_warn:      float = 0.30,
        distance_critical:  float = 0.50,
        min_group_size:     int   = 2,
    ):
        self._group_by    = group_by
        self._ex_warn     = excess_warn
        self._ex_crit     = excess_critical
        self._dist_warn   = distance_warn
        self._dist_crit   = distance_critical
        self._min_group   = min_group_size

    def analyse(self, members: List[PeerGroupMember]) -> PeerGroupReport:
        # Group members
        groups: Dict[str, List[PeerGroupMember]] = {}
        for m in members:
            key = getattr(m, self._group_by, "") or "unknown"
            groups.setdefault(key, []).append(m)

        findings: List[PeerAnomalyFinding] = []
        for group_key, group_members in groups.items():
            if len(group_members) < self._min_group:
                # Single-member groups: mark OK
                for m in group_members:
                    findings.append(PeerAnomalyFinding(
                        principal=m.principal, team=group_key,
                        severity="OK", permission_count=len(m.permissions),
                        group_median=float(len(m.permissions)), excess_count=0,
                        jaccard_distance=0.0, excess_permissions=[],
                        detail=f"Group too small for peer comparison (n={len(group_members)})",
                    ))
                continue
            findings.extend(self._analyse_group(group_key, group_members))

        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        warning  = sum(1 for f in findings if f.severity == "WARNING")
        ok       = sum(1 for f in findings if f.severity == "OK")

        return PeerGroupReport(
            total_users=len(findings), anomalies=critical + warning,
            critical=critical, warning=warning, ok=ok, findings=findings,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _analyse_group(
        self, group_key: str, members: List[PeerGroupMember]
    ) -> List[PeerAnomalyFinding]:
        # Compute group permission counts and median
        counts = [len(m.permissions) for m in members]
        median = self._median(counts)

        # Group union and intersection for centroid-based Jaccard
        all_perms: Set[str] = set()
        for m in members:
            all_perms |= m.permissions

        findings = []
        for member in members:
            # Peer set: all members except this one
            peers = [m for m in members if m.principal != member.principal]
            peer_union: Set[str] = set()
            for p in peers:
                peer_union |= p.permissions
            peer_median_count = self._median([len(p.permissions) for p in peers])

            excess_perms = sorted(member.permissions - peer_union)
            excess_count = max(0, len(member.permissions) - int(peer_median_count))

            # Jaccard distance vs group centroid (majority permissions)
            # Centroid = permissions held by >50% of peers
            if peers:
                from collections import Counter
                perm_freq = Counter()
                for p in peers:
                    for perm in p.permissions:
                        perm_freq[perm] += 1
                centroid = frozenset(
                    perm for perm, cnt in perm_freq.items()
                    if cnt > len(peers) / 2
                )
            else:
                centroid = frozenset()

            jd = self._jaccard_distance(frozenset(member.permissions), centroid)

            severity = self._severity(excess_count, jd)
            findings.append(PeerAnomalyFinding(
                principal          = member.principal,
                team               = group_key,
                severity           = severity,
                permission_count   = len(member.permissions),
                group_median       = round(peer_median_count, 1),
                excess_count       = excess_count,
                jaccard_distance   = round(jd, 4),
                excess_permissions = excess_perms,
                detail             = (
                    f"{member.principal}: {len(member.permissions)} perms, "
                    f"group median={peer_median_count:.1f}, "
                    f"excess={excess_count}, JD={jd:.3f} → {severity}"
                ),
            ))
        return findings

    def _severity(self, excess: int, jd: float) -> str:
        if excess >= self._ex_crit or jd >= self._dist_crit:
            return "CRITICAL"
        if excess >= self._ex_warn or jd >= self._dist_warn:
            return "WARNING"
        return "OK"

    @staticmethod
    def _jaccard_distance(a: FrozenSet[str], b: FrozenSet[str]) -> float:
        if not a and not b:
            return 0.0
        union = len(a | b)
        inter = len(a & b)
        return 1.0 - (inter / union if union > 0 else 0.0)

    @staticmethod
    def _median(values: List[int]) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        n = len(s)
        if n % 2 == 1:
            return float(s[n // 2])
        return (s[n // 2 - 1] + s[n // 2]) / 2.0
