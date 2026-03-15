"""
checkpoint_integrity.py  —  Checkpoint hash manifest and verifier
AI Fortress · Chapter 4 · Code Sample 4.B

Signs every checkpoint with a SHA-256 hash stored in a signed JSON manifest.
Before resuming training from a checkpoint, verifies the hash matches.
Detects adversarial checkpoint injection (swapping a legitimate checkpoint
with a backdoored one).

For production use: sign the manifest with an asymmetric key (e.g. Ed25519)
using the data-provenance-signing tools from Chapter 1 (Resource 1.C).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


class CheckpointTamperError(RuntimeError):
    pass


@dataclass
class CheckpointEntry:
    checkpoint_id: str
    path:          str
    sha256:        str
    size_bytes:    int
    registered_at: str
    epoch:         Optional[int] = None
    step:          Optional[int] = None
    metadata:      dict = field(default_factory=dict)


class CheckpointIntegrityManager:
    """
    Maintains a signed manifest of checkpoint hashes.

    Parameters
    ----------
    manifest_path : Path to the JSON manifest file
    """

    def __init__(self, manifest_path: str | Path):
        self.manifest_path = Path(manifest_path)
        self._manifest: Dict[str, CheckpointEntry] = {}
        if self.manifest_path.exists():
            self._load()

    def register(
        self,
        checkpoint_path: str | Path,
        epoch:    Optional[int] = None,
        step:     Optional[int] = None,
        metadata: dict = {},
    ) -> CheckpointEntry:
        """Hash a checkpoint file and add it to the manifest."""
        cp_path = Path(checkpoint_path)
        if not cp_path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {cp_path}")

        sha256     = self._hash_file(cp_path)
        size_bytes = cp_path.stat().st_size

        entry = CheckpointEntry(
            checkpoint_id = str(uuid.uuid4()),
            path          = str(cp_path.resolve()),
            sha256        = sha256,
            size_bytes    = size_bytes,
            registered_at = datetime.now(timezone.utc).isoformat(),
            epoch         = epoch,
            step          = step,
            metadata      = metadata,
        )
        self._manifest[str(cp_path.resolve())] = entry
        self._save()
        return entry

    def verify(self, checkpoint_path: str | Path) -> CheckpointEntry:
        """
        Verify a checkpoint's SHA-256 against the manifest.
        Raises CheckpointTamperError if the hash does not match.
        """
        cp_path = Path(checkpoint_path).resolve()
        key     = str(cp_path)

        if key not in self._manifest:
            raise CheckpointTamperError(
                f"Checkpoint '{cp_path}' is NOT in the manifest. "
                "It may have been injected without going through the registration step."
            )

        entry          = self._manifest[key]
        computed_hash  = self._hash_file(cp_path)

        if computed_hash != entry.sha256:
            raise CheckpointTamperError(
                f"Checkpoint '{cp_path}' FAILED integrity check!\n"
                f"  Manifest SHA-256 : {entry.sha256}\n"
                f"  Computed SHA-256 : {computed_hash}\n"
                "The checkpoint may have been replaced with a backdoored version."
            )
        return entry

    def verify_all(self) -> List[CheckpointEntry]:
        """Verify all registered checkpoints. Raises on first failure."""
        verified: List[CheckpointEntry] = []
        for path_key, entry in self._manifest.items():
            verified.append(self.verify(path_key))
        return verified

    def list_checkpoints(self) -> List[CheckpointEntry]:
        return list(self._manifest.values())

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: vars(v) for k, v in self._manifest.items()}
        self.manifest_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        for k, v in data.items():
            self._manifest[k] = CheckpointEntry(**v)

    @staticmethod
    def _hash_file(path: Path, chunk_size: int = 65536) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
