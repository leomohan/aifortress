"""
version_lineage.py  —  Model version lineage graph
AI Fortress · Chapter 12 · Code Sample 12.A

Records parent→child relationships between model versions to support:
  - Provenance tracing (which training data / base model produced this?)
  - Impact analysis (if base model is recalled, which fine-tunes are affected?)
  - Audit evidence for regulatory requirements (EU AI Act Art. 13)
  - Cycle detection (should never occur in a well-managed ML system)

Relationship types:
  fine_tune     — child is a fine-tune of parent
  distillation  — child is distilled from parent
  ensemble      — child ensemble includes parent as a component
  retrain       — child is a retrained version of parent on new data
  quantisation  — child is a quantised version of parent
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class LineageEdge:
    parent: str          # "model_name@version"
    child:  str
    rel:    str          # relationship type


@dataclass
class LineageNode:
    key:      str        # "model_name@version"
    parents:  List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)


@dataclass
class AncestryResult:
    subject:   str
    ancestors: List[str]          # all ancestor keys (BFS order)
    depth:     int                # longest path to a root


@dataclass
class CycleReport:
    has_cycle: bool
    cycles:    List[List[str]]


class VersionLineageGraph:
    """
    Directed acyclic graph of ML model version relationships.
    """

    def __init__(self):
        self._nodes: Dict[str, LineageNode] = {}
        self._edges: List[LineageEdge]      = []

    @staticmethod
    def _key(model_name: str, version: str) -> str:
        return f"{model_name}@{version}"

    def add_version(self, model_name: str, version: str) -> str:
        k = self._key(model_name, version)
        if k not in self._nodes:
            self._nodes[k] = LineageNode(key=k)
        return k

    def add_relationship(
        self,
        parent_model:   str,
        parent_version: str,
        child_model:    str,
        child_version:  str,
        rel:            str = "fine_tune",
    ) -> LineageEdge:
        """Register a parent→child relationship."""
        pk = self.add_version(parent_model, parent_version)
        ck = self.add_version(child_model,  child_version)
        edge = LineageEdge(parent=pk, child=ck, rel=rel)
        self._edges.append(edge)
        self._nodes[pk].children.append(ck)
        self._nodes[ck].parents.append(pk)
        return edge

    def ancestors(self, model_name: str, version: str) -> AncestryResult:
        """Return all ancestors of a version via BFS."""
        root    = self._key(model_name, version)
        visited: List[str] = []
        depths:  Dict[str, int] = {root: 0}
        queue   = deque([root])
        while queue:
            node = queue.popleft()
            for parent in self._nodes.get(node, LineageNode(node)).parents:
                if parent not in depths:
                    depths[parent] = depths[node] + 1
                    visited.append(parent)
                    queue.append(parent)
        return AncestryResult(
            subject   = root,
            ancestors = visited,
            depth     = max(depths.values()) if depths else 0,
        )

    def descendants(self, model_name: str, version: str) -> List[str]:
        """Return all descendants (BFS)."""
        root    = self._key(model_name, version)
        visited: Set[str] = set()
        queue   = deque([root])
        result: List[str] = []
        while queue:
            node = queue.popleft()
            for child in self._nodes.get(node, LineageNode(node)).children:
                if child not in visited:
                    visited.add(child)
                    result.append(child)
                    queue.append(child)
        return result

    def detect_cycles(self) -> CycleReport:
        WHITE, GREY, BLACK = 0, 1, 2
        colour: Dict[str, int] = {k: WHITE for k in self._nodes}
        cycles: List[List[str]] = []
        path:   List[str]       = []

        def dfs(node: str) -> None:
            colour[node] = GREY
            path.append(node)
            for child in self._nodes.get(node, LineageNode(node)).children:
                if colour.get(child, WHITE) == GREY:
                    idx = path.index(child)
                    cycles.append(list(path[idx:]) + [child])
                elif colour.get(child, WHITE) == WHITE:
                    dfs(child)
            path.pop()
            colour[node] = BLACK

        for node in list(self._nodes):
            if colour.get(node) == WHITE:
                dfs(node)
        return CycleReport(has_cycle=len(cycles) > 0, cycles=cycles)

    def roots(self) -> List[str]:
        """Return all versions with no parents."""
        return [k for k, n in self._nodes.items() if not n.parents]

    def leaves(self) -> List[str]:
        """Return all versions with no children."""
        return [k for k, n in self._nodes.items() if not n.children]

    def edges_for(self, model_name: str, version: str) -> List[LineageEdge]:
        k = self._key(model_name, version)
        return [e for e in self._edges if e.parent == k or e.child == k]

    def to_adjacency(self) -> Dict[str, List[str]]:
        return {k: list(n.children) for k, n in self._nodes.items()}
