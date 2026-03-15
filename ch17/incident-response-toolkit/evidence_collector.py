"""
evidence_collector.py  —  Forensic evidence collection for AI incidents
AI Fortress · Chapter 17 · Code Sample 17.A

Collects, hashes, and chains evidence artefacts for AI security incidents.
Each evidence item is SHA-256 hashed on ingestion to ensure integrity.
A hash chain links all evidence in collection order — any tampering
breaks the chain.

Evidence types: model_artefact | training_data_snapshot | inference_log |
  system_log | network_pcap | configuration | api_log | attestation_report
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class EvidenceItem:
    evidence_id:    str
    incident_id:    str
    evidence_type:  str
    description:    str
    content_hash:   str     # SHA-256 of content bytes
    chain_hash:     str     # SHA-256(prev_chain_hash + content_hash) — integrity chain
    size_bytes:     int
    collected_at:   str
    collector:      str
    sealed:         bool = False   # True once submitted to chain of custody


@dataclass
class EvidenceChain:
    incident_id:   str
    items:         List[EvidenceItem]
    chain_valid:   bool
    item_count:    int


class EvidenceCollector:
    """
    Collects and chains forensic evidence for an AI security incident.

    Parameters
    ----------
    incident_id : ID of the incident this collection belongs to.
    collector   : Identity of the person/service collecting evidence.
    storage_path: Optional path; if provided, writes a JSON manifest.
    """

    _GENESIS_HASH = "0" * 64   # sentinel for first item in chain

    def __init__(
        self,
        incident_id:  str,
        collector:    str = "ir-system",
        storage_path: Optional[str | Path] = None,
    ):
        self.incident_id = incident_id
        self._collector  = collector
        self._items:     List[EvidenceItem] = []
        self._path       = Path(storage_path) if storage_path else None
        self._last_chain = self._GENESIS_HASH

    def collect(
        self,
        content:       bytes,
        evidence_type: str,
        description:   str,
    ) -> EvidenceItem:
        """Hash and chain a piece of evidence."""
        content_hash = hashlib.sha256(content).hexdigest()
        chain_hash   = hashlib.sha256(
            (self._last_chain + content_hash).encode()
        ).hexdigest()

        item = EvidenceItem(
            evidence_id   = str(uuid.uuid4())[:8],
            incident_id   = self.incident_id,
            evidence_type = evidence_type,
            description   = description,
            content_hash  = content_hash,
            chain_hash    = chain_hash,
            size_bytes    = len(content),
            collected_at  = datetime.now(timezone.utc).isoformat(),
            collector     = self._collector,
        )
        self._items.append(item)
        self._last_chain = chain_hash
        if self._path:
            self._write_manifest()
        return item

    def seal(self, evidence_id: str) -> None:
        """Mark an evidence item as sealed (submitted to chain of custody)."""
        for item in self._items:
            if item.evidence_id == evidence_id:
                item.sealed = True
                if self._path:
                    self._write_manifest()
                return
        raise KeyError(f"Evidence '{evidence_id}' not found")

    def verify_chain(self) -> EvidenceChain:
        """Replay the hash chain to verify integrity."""
        prev = self._GENESIS_HASH
        valid = True
        for item in self._items:
            expected = hashlib.sha256(
                (prev + item.content_hash).encode()
            ).hexdigest()
            if not hmac.compare_digest(expected, item.chain_hash):
                valid = False
                break
            prev = item.chain_hash

        return EvidenceChain(
            incident_id = self.incident_id,
            items       = list(self._items),
            chain_valid = valid,
            item_count  = len(self._items),
        )

    def items(self) -> List[EvidenceItem]:
        return list(self._items)

    def _write_manifest(self) -> None:
        import dataclasses
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([dataclasses.asdict(i) for i in self._items], indent=2)
        )
