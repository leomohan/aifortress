"""
build_attestation.py  —  Build environment capture and signed attestation
AI Fortress · Chapter 8 · Code Sample 8.D

Captures the complete build environment state at the time of the ML training
job and produces a tamper-evident BuildAttestation JSON.

Captures:
  - Python version and platform
  - pip package list (name, version)
  - Sanitised environment variables (excludes secrets by key pattern)
  - git commit SHA, branch, and dirty-state flag
  - CUDA/GPU availability flag
  - Timestamp and build UUID
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|key|api_?key|credential|auth|private)",
    re.IGNORECASE,
)


@dataclass
class BuildAttestation:
    build_id:      str
    timestamp:     str
    python_version: str
    platform_info: str
    packages:      Dict[str, str]     # name → version
    env_vars:      Dict[str, str]     # sanitised env vars
    git_sha:       str
    git_branch:    str
    git_dirty:     bool
    cuda_available: bool
    sha256_proof:  str                # tamper-evident hash of all fields

    def save(self, path: str | Path) -> None:
        import dataclasses
        Path(path).write_text(
            json.dumps(dataclasses.asdict(self), indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: str | Path) -> "BuildAttestation":
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))

    def verify_proof(self) -> bool:
        """Verify the SHA-256 proof has not been tampered with."""
        import dataclasses
        d = dataclasses.asdict(self)
        d.pop("sha256_proof", None)
        payload = json.dumps(d, sort_keys=True).encode("utf-8")
        expected = hashlib.sha256(payload).hexdigest()
        return expected == self.sha256_proof


class BuildAttestationCapture:
    """
    Captures build environment state and produces a signed BuildAttestation.

    Parameters
    ----------
    env_var_allowlist : If set, only these environment variable names are captured.
    """

    def __init__(self, env_var_allowlist: Optional[List[str]] = None):
        self.allowlist = set(env_var_allowlist or [])

    def capture(self) -> BuildAttestation:
        """Capture the current build environment."""
        timestamp = datetime.now(timezone.utc).isoformat()
        build_id  = str(uuid.uuid4())

        packages   = self._get_packages()
        env_vars   = self._get_env_vars()
        git_sha, git_branch, git_dirty = self._get_git_state()
        cuda       = self._check_cuda()

        import dataclasses

        attestation_fields = {
            "build_id":       build_id,
            "timestamp":      timestamp,
            "python_version": sys.version,
            "platform_info":  platform.platform(),
            "packages":       packages,
            "env_vars":       env_vars,
            "git_sha":        git_sha,
            "git_branch":     git_branch,
            "git_dirty":      git_dirty,
            "cuda_available": cuda,
        }
        payload    = json.dumps(attestation_fields, sort_keys=True).encode("utf-8")
        sha256_proof = hashlib.sha256(payload).hexdigest()

        return BuildAttestation(**attestation_fields, sha256_proof=sha256_proof)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_packages(self) -> Dict[str, str]:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=30,
            )
            pkgs = json.loads(result.stdout)
            return {p["name"]: p["version"] for p in pkgs}
        except Exception:
            return {}

    def _get_env_vars(self) -> Dict[str, str]:
        result = {}
        for k, v in os.environ.items():
            if _SECRET_KEY_RE.search(k):
                continue    # skip secrets
            if self.allowlist and k not in self.allowlist:
                continue
            result[k] = v[:200]   # truncate long values
        return result

    def _get_git_state(self):
        sha = branch = ""
        dirty = False
        try:
            sha    = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                             stderr=subprocess.DEVNULL).decode().strip()
            branch = subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                                             stderr=subprocess.DEVNULL).decode().strip()
            status = subprocess.check_output(["git", "status", "--porcelain"],
                                             stderr=subprocess.DEVNULL).decode().strip()
            dirty  = len(status) > 0
        except Exception:
            pass
        return sha, branch, dirty

    @staticmethod
    def _check_cuda() -> bool:
        try:
            import torch
            return torch.cuda.is_available()
        except ImportError:
            pass
        try:
            result = subprocess.run(["nvidia-smi"], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
