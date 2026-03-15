"""
memory_isolation_verifier.py  —  Memory isolation checker for TrustZone deployments
AI Fortress · Chapter 15 · Code Sample 15.B

Verifies that memory region configuration satisfies TrustZone isolation
requirements. Checks TZASC (TrustZone Address Space Controller) rules,
ensures no Normal World mappings overlap with Secure World regions,
and validates that model weight memory is exclusively assigned to the TEE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class MemoryRegion:
    name:        str
    base_addr:   int    # byte address
    size_bytes:  int    # region size
    world:       str    # "secure" | "normal" | "shared"
    permissions: str    # "RWX" | "RW" | "RX" | "R" | "none"


@dataclass
class IsolationViolation:
    kind:        str    # "overlap" | "wrong_world" | "exec_in_normal" | "shared_model"
    region_a:    str
    region_b:    str
    detail:      str


@dataclass
class MemoryIsolationReport:
    valid:       bool
    violations:  List[IsolationViolation]
    checked_regions: int
    detail:      str


class MemoryIsolationVerifier:
    """
    Verifies memory isolation for TrustZone-based model protection.

    Rules enforced:
      1. No Secure World region overlaps with any Normal World region.
      2. Model weight regions must be in Secure World.
      3. Normal World must not have execute permission on shared regions.
      4. Regions labelled 'model-weights' must never be 'normal' or 'shared'.
    """

    def verify(
        self,
        regions:            List[MemoryRegion],
        model_region_names: Optional[List[str]] = None,
    ) -> MemoryIsolationReport:
        violations: List[IsolationViolation] = []
        model_names = set(model_region_names or [])

        secure_regions = [r for r in regions if r.world == "secure"]
        normal_regions = [r for r in regions if r.world == "normal"]

        # Rule 1: No overlap between secure and normal regions
        for sr in secure_regions:
            for nr in normal_regions:
                if self._overlaps(sr, nr):
                    violations.append(IsolationViolation(
                        kind     = "overlap",
                        region_a = sr.name,
                        region_b = nr.name,
                        detail   = (
                            f"Secure region '{sr.name}' "
                            f"[0x{sr.base_addr:08X}–0x{sr.base_addr+sr.size_bytes:08X}] "
                            f"overlaps Normal World region '{nr.name}'."
                        ),
                    ))

        # Rule 2 & 4: Model weight regions must be secure
        for r in regions:
            if r.name in model_names and r.world != "secure":
                violations.append(IsolationViolation(
                    kind     = "wrong_world",
                    region_a = r.name,
                    region_b = "",
                    detail   = (
                        f"Model region '{r.name}' is mapped to world='{r.world}'. "
                        "Model weights must reside in Secure World only."
                    ),
                ))

        # Rule 3: No execute permission on shared regions from Normal World perspective
        for r in regions:
            if r.world == "shared" and "X" in r.permissions:
                violations.append(IsolationViolation(
                    kind     = "exec_in_normal",
                    region_a = r.name,
                    region_b = "",
                    detail   = (
                        f"Shared region '{r.name}' has execute permission '{r.permissions}'. "
                        "Execute should never be granted on Normal World-accessible shared memory."
                    ),
                ))

        valid  = len(violations) == 0
        detail = (
            f"Memory isolation valid: {len(regions)} regions checked." if valid
            else f"{len(violations)} isolation violation(s) detected."
        )
        return MemoryIsolationReport(
            valid            = valid,
            violations       = violations,
            checked_regions  = len(regions),
            detail           = detail,
        )

    @staticmethod
    def _overlaps(a: MemoryRegion, b: MemoryRegion) -> bool:
        a_end = a.base_addr + a.size_bytes
        b_end = b.base_addr + b.size_bytes
        return a.base_addr < b_end and b.base_addr < a_end
