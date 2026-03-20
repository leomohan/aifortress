"""
chain.py  —  Chain-of-custody walker and full-chain verifier
AI Fortress · Chapter 1 · Code Sample 1.C

Walks a provenance chain from a leaf record back to the root, verifying
every Ed25519 signature along the way.  Any broken link, missing record,
or failed signature raises ChainVerificationError immediately.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List
from cryptography.exceptions import InvalidSignature
from provenance import ProvenanceRecord, verify_record, provenance_path_for
from keystore import find_public_key_for_fingerprint


class ChainVerificationError(Exception):
    pass


@dataclass
class ChainLink:
    record:    ProvenanceRecord
    verified:  bool
    depth:     int   # 0 = leaf, increases toward root


def verify_chain(
    leaf_provenance_path: Path,
    keys_dir:             Path,
    provenance_dir:       Path | None = None,
) -> List[ChainLink]:
    """
    Walk from leaf_provenance_path to the root, verifying every record.

    provenance_dir: directory to search for parent .provenance.json files.
                    Defaults to the same directory as the leaf record.

    Returns ordered list of ChainLink (leaf first, root last).
    Raises ChainVerificationError on any failure.
    """
    search_dir = provenance_dir or leaf_provenance_path.parent
    chain: List[ChainLink] = []
    current_path = leaf_provenance_path
    depth = 0
    visited: set[str] = set()

    while True:
        if not current_path.exists():
            raise ChainVerificationError(f"Provenance record not found: {current_path}")

        record = ProvenanceRecord.load(current_path)

        if record.record_id in visited:
            raise ChainVerificationError(
                f"Cycle detected in provenance chain at record {record.record_id}"
            )
        visited.add(record.record_id)

        # Find the public key for this record's signer
        public_key = find_public_key_for_fingerprint(record.signer_fingerprint, keys_dir)
        if public_key is None:
            raise ChainVerificationError(
                f"No public key found for fingerprint {record.signer_fingerprint} "
                f"(record {record.record_id}, stage '{record.pipeline_stage}')"
            )

        try:
            verify_record(record, public_key)
        except InvalidSignature:
            raise ChainVerificationError(
                f"Signature INVALID on record {record.record_id} "
                f"(stage '{record.pipeline_stage}', artifact '{record.artifact_path}')"
            )

        chain.append(ChainLink(record=record, verified=True, depth=depth))

        if record.is_root:
            break

        # Locate parent record file
        parent_path = _find_parent_record(record.parent_record_id, search_dir)
        if parent_path is None:
            raise ChainVerificationError(
                f"Parent record {record.parent_record_id} not found in {search_dir}"
            )
        current_path = parent_path
        depth += 1

    return chain


def _find_parent_record(parent_id: str, search_dir: Path) -> Path | None:
    """Search for a .provenance.json file containing the given record_id."""
    import json
    for pf in search_dir.rglob("*.provenance.json"):
        try:
            data = json.loads(pf.read_text(encoding="utf-8"))
            if data.get("record_id") == parent_id:
                return pf
        except Exception:
            continue
    return None


def print_chain(chain: List[ChainLink]) -> None:
    """Pretty-print a verified chain."""
    print(f"\nProvenance chain ({len(chain)} records):")
    print("=" * 60)
    for link in chain:
        r = link.record
        status = "✓ VERIFIED" if link.verified else "✗ FAILED"
        indent = "  " * link.depth
        print(f"{indent}[depth={link.depth}] {status}")
        print(f"{indent}  Stage      : {r.pipeline_stage}")
        print(f"{indent}  Record ID  : {r.record_id}")
        print(f"{indent}  Artifact   : {r.artifact_path}")
        print(f"{indent}  SHA-256    : {r.artifact_sha256[:16]}...")
        print(f"{indent}  Signed at  : {r.signed_at}")
        if r.transformation:
            print(f"{indent}  Transform  : {r.transformation}")
        if r.is_root:
            print(f"{indent}  Source URI : {r.source_uri}")
            print(f"{indent}  [ROOT]")
        print()
