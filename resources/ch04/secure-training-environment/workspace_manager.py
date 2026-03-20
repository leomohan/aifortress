"""
workspace_manager.py  —  Ephemeral workspace with cryptographic wipe
AI Fortress · Chapter 4 · Code Sample 4.A

Creates a per-job isolated workspace directory with strict permissions
and registers a shutdown hook to cryptographically wipe the workspace
on job completion, failure, or signal (SIGTERM/SIGINT).

Cryptographic wipe (DoD 5220.22-M inspired):
  Pass 1 — overwrite with zeros
  Pass 2 — overwrite with ones (0xFF)
  Pass 3 — overwrite with random bytes
  Then: truncate, unlink

This is a best-effort wipe for spinning disks and some SSDs.
For SSDs, use hardware-level encryption + key destruction instead.
"""
from __future__ import annotations

import atexit
import os
import secrets
import shutil
import signal
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class WorkspaceInfo:
    job_id:     str
    path:       Path
    created_at: str
    wiped:      bool = False


class WorkspaceManager:
    """
    Context manager for an isolated, ephemeral training job workspace.

    Usage:
        with WorkspaceManager(job_id="train-001", base_dir="/tmp/training") as ws:
            data_path = ws.path / "data"
            data_path.mkdir()
            # ... train ...
        # workspace is wiped on exit regardless of success/failure

    Parameters
    ----------
    job_id       : Unique identifier for this job (used in directory name)
    base_dir     : Parent directory for the workspace (default: system temp)
    n_wipe_passes: Number of overwrite passes (default 3; 0 = simple delete)
    """

    def __init__(
        self,
        job_id:        str,
        base_dir:      Optional[str] = None,
        n_wipe_passes: int = 3,
    ):
        self.job_id        = job_id
        self.base_dir      = base_dir
        self.n_wipe_passes = n_wipe_passes
        self._workspace:   Optional[WorkspaceInfo] = None
        self._registered   = False

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> WorkspaceInfo:
        self._workspace = self._create()
        self._install_hooks()
        return self._workspace

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.wipe()
        return False   # do not suppress exceptions

    # ── Workspace creation ────────────────────────────────────────────────────

    def _create(self) -> WorkspaceInfo:
        from datetime import datetime, timezone
        parent = Path(self.base_dir) if self.base_dir else Path(tempfile.gettempdir())
        parent.mkdir(parents=True, exist_ok=True)

        ws_path = parent / f"aif_job_{self.job_id}_{secrets.token_hex(8)}"
        ws_path.mkdir(mode=0o700)   # owner read/write/execute only

        # Create standard sub-directories
        for sub in ["data", "checkpoints", "logs", "tmp"]:
            (ws_path / sub).mkdir(mode=0o700)

        return WorkspaceInfo(
            job_id     = self.job_id,
            path       = ws_path,
            created_at = datetime.now(timezone.utc).isoformat(),
        )

    # ── Cryptographic wipe ────────────────────────────────────────────────────

    def wipe(self) -> bool:
        """Cryptographically wipe and remove the workspace. Returns True if successful."""
        if self._workspace is None or self._workspace.wiped:
            return True

        ws_path = self._workspace.path
        if not ws_path.exists():
            self._workspace.wiped = True
            return True

        try:
            self._wipe_directory(ws_path)
            self._workspace.wiped = True
            return True
        except Exception as e:
            # Log but do not re-raise — wipe failure must not block job completion
            import logging
            logging.getLogger(__name__).error(
                f"Workspace wipe failed for {ws_path}: {e}. "
                "Manual cleanup required."
            )
            return False

    def _wipe_directory(self, path: Path) -> None:
        """Recursively wipe all files in a directory, then remove it."""
        for child in path.rglob("*"):
            if child.is_file():
                self._wipe_file(child)
        shutil.rmtree(path, ignore_errors=True)

    def _wipe_file(self, file_path: Path) -> None:
        """Multi-pass overwrite of a single file."""
        if self.n_wipe_passes == 0:
            file_path.unlink(missing_ok=True)
            return

        try:
            size = file_path.stat().st_size
            if size == 0:
                file_path.unlink(missing_ok=True)
                return

            # Ensure we can write
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)

            with open(file_path, "r+b") as f:
                for pass_num in range(self.n_wipe_passes):
                    f.seek(0)
                    if pass_num == 0:
                        f.write(b"\x00" * size)       # zeros
                    elif pass_num == 1:
                        f.write(b"\xFF" * size)       # ones
                    else:
                        f.write(secrets.token_bytes(size))  # random
                    f.flush()
                    os.fsync(f.fileno())

            file_path.unlink()
        except (OSError, PermissionError):
            file_path.unlink(missing_ok=True)

    # ── Signal and atexit hooks ───────────────────────────────────────────────

    def _install_hooks(self) -> None:
        if self._registered:
            return
        atexit.register(self.wipe)

        def _signal_handler(signum, frame):
            self.wipe()
            # Re-raise the default handler
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _signal_handler)
            except (OSError, ValueError):
                pass   # Can't install signal handlers in some environments (threads)

        self._registered = True


@contextmanager
def ephemeral_workspace(job_id: str, base_dir: Optional[str] = None, n_wipe_passes: int = 3):
    """Convenience context manager — thin wrapper around WorkspaceManager."""
    with WorkspaceManager(job_id=job_id, base_dir=base_dir, n_wipe_passes=n_wipe_passes) as ws:
        yield ws
