"""
permission_graph.py  —  Role permission inheritance graph for ML IAM
AI Fortress · Chapter 11 · Code Sample 11.A

Builds and analyses a directed acyclic graph (DAG) of role relationships
to support permission inheritance resolution, cycle detection, and
over-privilege analysis.

Analyses provided:
  - Effective permission set for any role (DFS traversal)
  - Cycle detection in the inheritance graph (DFS with colour marking)
  - Permission blast radius: given a permission, which roles grant it?
  - Over-privilege paths: roles with more permissions than necessary
    for their position in the hierarchy
  - Role comparison: which permissions does role A have that role B lacks?
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass
class RoleNode:
    name:        str
    permissions: FrozenSet[str]
    parents:     List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class CycleReport:
    has_cycle: bool
    cycles:    List[List[str]]   # each inner list is a cycle path


@dataclass
class GraphAnalysis:
    roles:                 List[str]
    effective_permissions: Dict[str, List[str]]   # role → sorted permission list
    cycles:                CycleReport
    blast_radius:          Dict[str, List[str]]   # permission → roles that grant it
    over_privileged_paths: List[str]              # roles with more perms than parents sum


class PermissionGraph:
    """
    Directed acyclic graph of role relationships for ML IAM analysis.
    """

    def __init__(self):
        self._nodes: Dict[str, RoleNode] = {}

    def add_role(
        self,
        name:        str,
        permissions: Set[str],
        parents:     Optional[List[str]] = None,
        description: str = "",
    ) -> "PermissionGraph":
        self._nodes[name] = RoleNode(
            name        = name,
            permissions = frozenset(permissions),
            parents     = parents or [],
            description = description,
        )
        return self

    @classmethod
    def from_rbac_engine(cls, engine) -> "PermissionGraph":
        """Build a PermissionGraph from an RBACEngine instance."""
        from rbac_engine import _ROLE_PARENTS, _ROLE_PERMISSIONS
        g = cls()
        for role, perms in engine._role_perms.items():
            parents = _ROLE_PARENTS.get(role, [])
            g.add_role(role, set(perms), parents=parents)
        return g

    # ── Analysis methods ──────────────────────────────────────────────────────

    def effective_permissions(self, role: str) -> FrozenSet[str]:
        """Return all permissions for `role` including inherited ones."""
        return self._collect_permissions(role, visited=set())

    def detect_cycles(self) -> CycleReport:
        """Detect cycles in the inheritance graph using DFS with colour marking."""
        WHITE, GREY, BLACK = 0, 1, 2
        colour  = {r: WHITE for r in self._nodes}
        cycles: List[List[str]] = []
        path:   List[str]       = []

        def dfs(node: str) -> None:
            colour[node] = GREY
            path.append(node)
            for parent in self._nodes.get(node, RoleNode(node, frozenset())).parents:
                if parent not in colour:
                    continue
                if colour[parent] == GREY:
                    # Found a back edge — record cycle
                    idx    = path.index(parent)
                    cycles.append(list(path[idx:]) + [parent])
                elif colour[parent] == WHITE:
                    dfs(parent)
            path.pop()
            colour[node] = BLACK

        for role in list(self._nodes):
            if colour.get(role) == WHITE:
                dfs(role)

        return CycleReport(has_cycle=len(cycles) > 0, cycles=cycles)

    def blast_radius(self, permission: str) -> List[str]:
        """Return all roles (directly or via inheritance) that grant `permission`."""
        return sorted(
            r for r in self._nodes
            if permission in self.effective_permissions(r)
        )

    def compare_roles(self, role_a: str, role_b: str) -> Dict[str, List[str]]:
        """Return permissions that A has but B lacks, and vice versa."""
        a = self.effective_permissions(role_a)
        b = self.effective_permissions(role_b)
        return {
            f"{role_a}_only": sorted(a - b),
            f"{role_b}_only": sorted(b - a),
            "shared":         sorted(a & b),
        }

    def analyse(self) -> GraphAnalysis:
        """Run a full graph analysis."""
        eff_perms = {
            r: sorted(self.effective_permissions(r))
            for r in self._nodes
        }
        blast: Dict[str, List[str]] = {}
        all_perms = set()
        for perms in eff_perms.values():
            all_perms |= set(perms)
        for perm in sorted(all_perms):
            blast[perm] = self.blast_radius(perm)

        # Over-privilege: a role with strictly more permissions than any single parent
        over_priv = []
        for role, node in self._nodes.items():
            if not node.parents:
                continue
            role_perms = self.effective_permissions(role)
            own_perms  = node.permissions
            inherited  = frozenset().union(
                *(self.effective_permissions(p) for p in node.parents)
            )
            own_unique = own_perms - inherited
            if len(own_unique) > len(inherited) * 0.5:   # heuristic: >50% extra
                over_priv.append(
                    f"{role} adds {len(own_unique)} unique permissions "
                    f"beyond {len(inherited)} inherited"
                )

        return GraphAnalysis(
            roles                 = sorted(self._nodes),
            effective_permissions = eff_perms,
            cycles                = self.detect_cycles(),
            blast_radius          = blast,
            over_privileged_paths = over_priv,
        )

    def shortest_path_to_permission(
        self, start_role: str, permission: str
    ) -> Optional[List[str]]:
        """BFS to find the shortest inheritance path that grants `permission`."""
        from collections import deque
        queue: deque = deque([[start_role]])
        seen:  set   = {start_role}
        while queue:
            path = queue.popleft()
            role = path[-1]
            node = self._nodes.get(role)
            if node is None:
                continue
            if permission in node.permissions:
                return path
            for parent in node.parents:
                if parent not in seen:
                    seen.add(parent)
                    queue.append(path + [parent])
        return None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _collect_permissions(self, role: str, visited: Set[str]) -> FrozenSet[str]:
        if role in visited:
            return frozenset()
        visited.add(role)
        node = self._nodes.get(role)
        if node is None:
            return frozenset()
        perms: Set[str] = set(node.permissions)
        for parent in node.parents:
            perms |= self._collect_permissions(parent, visited)
        return frozenset(perms)
