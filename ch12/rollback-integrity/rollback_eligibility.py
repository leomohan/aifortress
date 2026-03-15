"""
rollback_eligibility.py  —  Pre-rollback validation for ML model versions
AI Fortress · Chapter 12 · Code Sample 12.C

Validates that a target version is eligible for rollback before any swap
is attempted. All checks must pass for a rollback to proceed.

Checks performed:
  ARTEFACT_INTEGRITY  — SHA-256 hash of target matches the registry record
  STAGE_ELIGIBILITY   — target version previously reached the required stage
  NOT_QUARANTINED     — target version is not flagged as security-compromised
  VERSION_FLOOR       — target version is not below the configured minimum safe version
  NOT_CURRENT         — target is not already the active version (no-op protection)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from version_registry import compare_semver


_ALL_CHECKS = {
    "ARTEFACT_INTEGRITY",
    "STAGE_ELIGIBILITY",
    "NOT_QUARANTINED",
    "VERSION_FLOOR",
    "NOT_CURRENT",
}


@dataclass
class EligibilityResult:
    eligible:     bool
    model_name:   str
    target_version: str
    checks_passed: List[str]
    checks_failed: List[str]
    details:       Dict[str, str]   # check → detail message

    def summary(self) -> str:
        icon = "✅" if self.eligible else "❌"
        return (
            f"{icon} Rollback eligibility for {self.model_name}@{self.target_version}: "
            f"{len(self.checks_passed)} passed, {len(self.checks_failed)} failed."
        )


class RollbackEligibilityChecker:
    """
    Validates pre-rollback conditions for a model version.

    Parameters
    ----------
    quarantined_versions : Set of "model@version" strings blocked from use.
    min_version_floor    : Per-model minimum safe version. Rollback below
                           this is rejected. Dict of model_name → version str.
    stage_history_fn     : Callable(model_name, version) → List[str] of stages
                           the version has previously reached. Used to confirm
                           the target was once deployed to the required stage.
    hash_lookup_fn       : Callable(model_name, version) → str | None.
                           Returns stored SHA-256 for a version, or None.
    """

    def __init__(
        self,
        quarantined_versions: Optional[Set[str]] = None,
        min_version_floor:    Optional[Dict[str, str]] = None,
        stage_history_fn:     Optional[Callable] = None,
        hash_lookup_fn:       Optional[Callable] = None,
    ):
        self._quarantined = quarantined_versions or set()
        self._floor       = min_version_floor or {}
        self._stage_fn    = stage_history_fn
        self._hash_fn     = hash_lookup_fn

    def check(
        self,
        model_name:      str,
        target_version:  str,
        current_version: str,
        target_hash:     Optional[str] = None,  # actual hash of target artefact on disk
        required_stage:  str = "production",
    ) -> EligibilityResult:
        passed: List[str]       = []
        failed: List[str]       = []
        details: Dict[str, str] = {}

        # 1. NOT_CURRENT
        if target_version == current_version:
            failed.append("NOT_CURRENT")
            details["NOT_CURRENT"] = f"Target {target_version} is already the active version."
        else:
            passed.append("NOT_CURRENT")
            details["NOT_CURRENT"] = "Target differs from current version."

        # 2. NOT_QUARANTINED
        key = f"{model_name}@{target_version}"
        if key in self._quarantined:
            failed.append("NOT_QUARANTINED")
            details["NOT_QUARANTINED"] = f"Version {target_version} is quarantined (security flag)."
        else:
            passed.append("NOT_QUARANTINED")
            details["NOT_QUARANTINED"] = "Version not quarantined."

        # 3. VERSION_FLOOR
        floor = self._floor.get(model_name)
        if floor:
            if compare_semver(target_version, floor) < 0:
                failed.append("VERSION_FLOOR")
                details["VERSION_FLOOR"] = (
                    f"Target {target_version} is below minimum safe version {floor}."
                )
            else:
                passed.append("VERSION_FLOOR")
                details["VERSION_FLOOR"] = f"Target {target_version} >= floor {floor}."
        else:
            passed.append("VERSION_FLOOR")
            details["VERSION_FLOOR"] = "No version floor configured."

        # 4. STAGE_ELIGIBILITY
        if self._stage_fn:
            history = self._stage_fn(model_name, target_version)
            if required_stage in history:
                passed.append("STAGE_ELIGIBILITY")
                details["STAGE_ELIGIBILITY"] = (
                    f"Version {target_version} previously reached '{required_stage}'."
                )
            else:
                failed.append("STAGE_ELIGIBILITY")
                details["STAGE_ELIGIBILITY"] = (
                    f"Version {target_version} has not reached '{required_stage}'. "
                    f"History: {history}"
                )
        else:
            passed.append("STAGE_ELIGIBILITY")
            details["STAGE_ELIGIBILITY"] = "No stage history function configured (skipped)."

        # 5. ARTEFACT_INTEGRITY
        if self._hash_fn and target_hash:
            stored = self._hash_fn(model_name, target_version)
            if stored and stored == target_hash:
                passed.append("ARTEFACT_INTEGRITY")
                details["ARTEFACT_INTEGRITY"] = "SHA-256 digest matches registry record."
            elif stored:
                failed.append("ARTEFACT_INTEGRITY")
                details["ARTEFACT_INTEGRITY"] = (
                    f"Hash mismatch: registry={stored[:16]}…, actual={target_hash[:16]}…"
                )
            else:
                failed.append("ARTEFACT_INTEGRITY")
                details["ARTEFACT_INTEGRITY"] = "No hash record found in registry."
        elif target_hash is None and self._hash_fn:
            failed.append("ARTEFACT_INTEGRITY")
            details["ARTEFACT_INTEGRITY"] = "target_hash not provided — cannot verify integrity."
        else:
            passed.append("ARTEFACT_INTEGRITY")
            details["ARTEFACT_INTEGRITY"] = "Integrity check skipped (no hash function configured)."

        return EligibilityResult(
            eligible       = len(failed) == 0,
            model_name     = model_name,
            target_version = target_version,
            checks_passed  = passed,
            checks_failed  = failed,
            details        = details,
        )

    def quarantine(self, model_name: str, version: str) -> None:
        self._quarantined.add(f"{model_name}@{version}")

    def set_floor(self, model_name: str, min_version: str) -> None:
        self._floor[model_name] = min_version
