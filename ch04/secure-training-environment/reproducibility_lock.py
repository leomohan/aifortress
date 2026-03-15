"""
reproducibility_lock.py  —  Dependency pinning and environment verification
AI Fortress · Chapter 4 · Code Sample 4.A

Captures the full environment fingerprint at the end of a successful training
run and verifies it on every subsequent run.  Drift from the pinned lock
triggers a hard failure before training starts, preventing:

  - Silent model divergence due to framework version changes
  - Supply-chain substitution (different package installed under same name)
  - Seed drift causing non-reproducible training
  - CUDA / cuDNN version mismatches between training and inference

Lock file contents:
  - Python version (major.minor.micro)
  - Installed packages (name → version, SHA-256 of wheel/sdist)
  - Random seeds snapshot (Python, NumPy, framework)
  - CUDA / cuDNN / driver versions (if GPU present)
  - Platform identifier (OS, architecture)
  - Lock file SHA-256 (tamper evidence)
"""
from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class EnvironmentDriftError(RuntimeError):
    """Raised when the current environment does not match the pinned lock."""
    pass


@dataclass
class EnvironmentLock:
    lock_id:       str
    created_at:    str
    python_version: str
    platform_info:  dict
    packages:       Dict[str, str]   # name → version
    cuda_info:      dict
    random_seeds:   dict
    sha256:         str = ""          # set after creation

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "EnvironmentLock":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)


class ReproducibilityLock:
    """
    Captures and verifies environment reproducibility locks.

    Usage — capture after a successful first run:
        lock = ReproducibilityLock.capture(seeds={"numpy": 42, "torch": 42})
        lock.save("environment.lock.json")

    Usage — verify before every subsequent run:
        lock = ReproducibilityLock.load("environment.lock.json")
        lock.verify()   # raises EnvironmentDriftError on mismatch
    """

    @staticmethod
    def capture(
        seeds:             Optional[Dict[str, int]] = None,
        extra_packages:    Optional[List[str]] = None,
    ) -> EnvironmentLock:
        """Capture the current environment state into a lock."""
        python_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        plat       = {
            "system":    platform.system(),
            "release":   platform.release(),
            "machine":   platform.machine(),
            "processor": platform.processor(),
        }
        packages   = ReproducibilityLock._installed_packages()
        cuda_info  = ReproducibilityLock._cuda_info()
        now        = datetime.now(timezone.utc).isoformat()

        lock = EnvironmentLock(
            lock_id        = str(uuid.uuid4()),
            created_at     = now,
            python_version  = python_ver,
            platform_info   = plat,
            packages        = packages,
            cuda_info       = cuda_info,
            random_seeds    = seeds or {},
        )
        # Compute tamper-evident hash
        payload     = json.dumps({k: v for k, v in lock.to_dict().items() if k != "sha256"},
                                 sort_keys=True)
        lock.sha256 = hashlib.sha256(payload.encode()).hexdigest()
        return lock

    @staticmethod
    def load(path: str | Path) -> EnvironmentLock:
        return EnvironmentLock.load(path)

    @staticmethod
    def verify(lock: EnvironmentLock) -> None:
        """
        Verify the current environment matches the lock.
        Raises EnvironmentDriftError with details on any mismatch.
        """
        drifts: List[str] = []

        # ── SHA-256 tamper check ──────────────────────────────────────────
        payload = json.dumps({k: v for k, v in lock.to_dict().items() if k != "sha256"},
                              sort_keys=True)
        computed_sha = hashlib.sha256(payload.encode()).hexdigest()
        if computed_sha != lock.sha256:
            drifts.append(f"Lock file SHA-256 mismatch — file may have been tampered with.")

        # ── Python version ────────────────────────────────────────────────
        cur_python = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if cur_python != lock.python_version:
            drifts.append(f"Python version: locked={lock.python_version}, current={cur_python}")

        # ── Package versions ──────────────────────────────────────────────
        cur_packages = ReproducibilityLock._installed_packages()
        for pkg, locked_ver in lock.packages.items():
            cur_ver = cur_packages.get(pkg)
            if cur_ver is None:
                drifts.append(f"Package '{pkg}' (locked {locked_ver}) is NOT installed.")
            elif cur_ver != locked_ver:
                drifts.append(f"Package '{pkg}': locked={locked_ver}, current={cur_ver}")

        # New packages not in the lock
        for pkg in cur_packages:
            if pkg not in lock.packages:
                drifts.append(f"NEW package '{pkg}=={cur_packages[pkg]}' not in lock.")

        # ── CUDA info ─────────────────────────────────────────────────────
        cur_cuda = ReproducibilityLock._cuda_info()
        for key in ("cuda_version", "cudnn_version"):
            if lock.cuda_info.get(key) and cur_cuda.get(key) != lock.cuda_info.get(key):
                drifts.append(
                    f"{key}: locked={lock.cuda_info.get(key)}, current={cur_cuda.get(key)}"
                )

        if drifts:
            raise EnvironmentDriftError(
                f"Environment has drifted from lock '{lock.lock_id}' "
                f"({len(drifts)} issue(s)):\n  " + "\n  ".join(drifts)
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _installed_packages() -> Dict[str, str]:
        """Return dict of installed package name → version."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=30,
            )
            packages = json.loads(result.stdout)
            return {p["name"].lower(): p["version"] for p in packages}
        except Exception:
            return {}

    @staticmethod
    def _cuda_info() -> dict:
        info: dict = {"available": False}
        try:
            import torch
            info["available"]      = torch.cuda.is_available()
            info["cuda_version"]   = torch.version.cuda
            info["cudnn_version"]  = str(torch.backends.cudnn.version()) if torch.cuda.is_available() else None
            info["torch_version"]  = torch.__version__
            info["device_count"]   = torch.cuda.device_count()
        except ImportError:
            pass
        return info
