"""
load_guard.py  —  Safe model loader with mandatory signature verification
AI Fortress · Chapter 6 · Code Sample 6.A

Drop-in wrapper around model loading that enforces:
  1. Signature manifest exists and all signatures verify
  2. Required signing roles are present (e.g. trainer + reviewer)
  3. Artefact SHA-256 matches the manifest
  4. Optional: model name/version matches expected values

Raises UnsignedModelError or TamperedModelError — never silently loads.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from signature_verifier import SignatureVerifier, VerificationResult


class UnsignedModelError(RuntimeError):
    """Raised when a model has no valid signature manifest."""


class TamperedModelError(RuntimeError):
    """Raised when a model's signature verification fails."""


class SafeModelLoader:
    """
    Enforces signature verification before returning a loaded model object.

    Parameters
    ----------
    required_roles : Signing roles that must be present (e.g. ["trainer", "reviewer"]).
    trusted_keys   : Optional signer_id → PEM bytes mapping for key pinning.
    expected_name  : If set, model_name in manifest must match.
    expected_version: If set, model_version in manifest must match.
    """

    def __init__(
        self,
        required_roles:   Optional[List[str]] = None,
        trusted_keys:     Optional[dict] = None,
        expected_name:    Optional[str] = None,
        expected_version: Optional[str] = None,
    ):
        self._verifier = SignatureVerifier(
            required_roles=required_roles,
            trusted_keys=trusted_keys,
        )
        self.expected_name    = expected_name
        self.expected_version = expected_version

    def verify_only(self, model_path: str | Path) -> VerificationResult:
        """Verify without loading. Returns VerificationResult."""
        result = self._verifier.verify(model_path)
        self._check_result(model_path, result)
        return result

    def load_bytes(self, model_path: str | Path) -> bytes:
        """Verify, then return raw file bytes. For use with custom loaders."""
        result = self._verifier.verify(model_path)
        self._check_result(model_path, result)
        return Path(model_path).read_bytes()

    def load_with(self, model_path: str | Path, loader_fn) -> object:
        """
        Verify, then call loader_fn(path) → model_object.

        Example:
            import torch
            model = guard.load_with("model.pt", torch.load)
        """
        result = self._verifier.verify(model_path)
        self._check_result(model_path, result)
        return loader_fn(model_path)

    def _check_result(self, path, result: VerificationResult) -> None:
        if not result.verified_signers and not result.valid:
            raise UnsignedModelError(
                f"Model '{path}' has no valid signatures. Errors: {result.errors}"
            )
        if not result.valid:
            raise TamperedModelError(
                f"Model '{path}' failed signature verification. "
                f"Errors: {result.errors}. "
                f"Failed signers: {result.failed_signers}"
            )
        if self.expected_name and result.model_name != self.expected_name:
            raise TamperedModelError(
                f"Model name mismatch: expected '{self.expected_name}', "
                f"got '{result.model_name}'."
            )
        if self.expected_version and result.model_version != self.expected_version:
            raise TamperedModelError(
                f"Model version mismatch: expected '{self.expected_version}', "
                f"got '{result.model_version}'."
            )
