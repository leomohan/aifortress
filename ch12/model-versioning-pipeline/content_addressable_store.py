"""
content_addressable_store.py  —  Content-addressable model artefact store
AI Fortress · Chapter 12 · Code Sample 12.A

Stores model artefact metadata keyed by SHA-256 content hash.
Prevents silent substitution by binding (model_name, version) → hash,
and detecting hash mismatches on retrieval.

This module stores metadata only (hashes, sizes, signatures).
Actual artefact bytes are assumed stored separately (S3, GCS, etc.)
and referenced by their content hash.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ArtefactEntry:
    sha256:       str
    model_name:   str
    version:      str
    size_bytes:   int
    stored_at:    str
    storage_uri:  str = ""       # s3://bucket/path/sha256 etc.
    signed:       bool = False
    signature:    str  = ""
    signer:       str  = ""
    tags:         List[str] = field(default_factory=list)


@dataclass
class LookupResult:
    found:        bool
    entry:        Optional[ArtefactEntry]
    tampered:     bool   # True if found but hash doesn't match expected
    reason:       str


class ContentAddressableStore:
    """
    Content-addressable store for ML model artefact metadata.

    Parameters
    ----------
    store_path : Optional JSON file to persist the store across sessions.
    """

    def __init__(self, store_path: Optional[str | Path] = None):
        self._by_hash:    Dict[str, ArtefactEntry] = {}
        self._by_coords:  Dict[tuple, str] = {}       # (model, version) → sha256
        self._store_path  = Path(store_path) if store_path else None
        if self._store_path and self._store_path.exists():
            self._load()

    def put(
        self,
        sha256:      str,
        model_name:  str,
        version:     str,
        size_bytes:  int,
        storage_uri: str = "",
        signed:      bool = False,
        signature:   str  = "",
        signer:      str  = "",
        tags:        Optional[List[str]] = None,
    ) -> ArtefactEntry:
        """
        Register an artefact by content hash.
        Raises ValueError if the same (model, version) is already registered
        with a different hash (substitution attempt detected).
        """
        coords = (model_name, version)
        if coords in self._by_coords:
            existing_hash = self._by_coords[coords]
            if existing_hash != sha256:
                raise ValueError(
                    f"Hash mismatch for {model_name}@{version}: "
                    f"existing={existing_hash[:16]}…, new={sha256[:16]}…. "
                    "Possible artefact substitution — registration rejected."
                )
            # Idempotent re-registration of same hash
            return self._by_hash[existing_hash]

        entry = ArtefactEntry(
            sha256      = sha256,
            model_name  = model_name,
            version     = version,
            size_bytes  = size_bytes,
            stored_at   = datetime.now(timezone.utc).isoformat(),
            storage_uri = storage_uri,
            signed      = signed,
            signature   = signature,
            signer      = signer,
            tags        = tags or [],
        )
        self._by_hash[sha256]   = entry
        self._by_coords[coords] = sha256
        self._persist()
        return entry

    def get_by_hash(self, sha256: str) -> LookupResult:
        entry = self._by_hash.get(sha256)
        if entry is None:
            return LookupResult(found=False, entry=None, tampered=False,
                                reason="Hash not found in store")
        return LookupResult(found=True, entry=entry, tampered=False,
                            reason="Found by content hash")

    def get_by_version(
        self,
        model_name: str,
        version:    str,
        verify_hash: Optional[str] = None,
    ) -> LookupResult:
        """
        Look up an artefact by (model_name, version).
        If verify_hash is provided, confirm the stored hash matches.
        """
        coords = (model_name, version)
        sha256 = self._by_coords.get(coords)
        if sha256 is None:
            return LookupResult(found=False, entry=None, tampered=False,
                                reason=f"No artefact registered for {model_name}@{version}")
        entry = self._by_hash.get(sha256)
        if entry is None:
            return LookupResult(found=False, entry=None, tampered=True,
                                reason="Index inconsistency — possible tampering")

        if verify_hash and verify_hash != sha256:
            return LookupResult(found=True, entry=entry, tampered=True,
                                reason=f"Hash mismatch: expected={verify_hash[:16]}…, "
                                       f"stored={sha256[:16]}…")
        return LookupResult(found=True, entry=entry, tampered=False,
                            reason="Found by version coordinates")

    def list_versions(self, model_name: str) -> List[str]:
        return sorted(
            version for (mn, version) in self._by_coords
            if mn == model_name
        )

    def total_entries(self) -> int:
        return len(self._by_hash)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist(self) -> None:
        if not self._store_path:
            return
        import dataclasses
        data = {
            "entries": [dataclasses.asdict(e) for e in self._by_hash.values()]
        }
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        self._store_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> None:
        data = json.loads(self._store_path.read_text(encoding="utf-8"))
        for raw in data.get("entries", []):
            entry  = ArtefactEntry(**{k: v for k, v in raw.items()})
            coords = (entry.model_name, entry.version)
            self._by_hash[entry.sha256] = entry
            self._by_coords[coords]     = entry.sha256
