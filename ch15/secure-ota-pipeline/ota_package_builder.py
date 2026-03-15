"""
ota_package_builder.py  —  Signed OTA update package builder
AI Fortress · Chapter 15 · Code Sample 15.C

Builds cryptographically signed OTA update packages for edge AI devices.
Each package contains:
  - Payload bytes (model weights, firmware, or config)
  - Metadata (target version, device class, rollback version)
  - HMAC-SHA256 signature over payload + metadata
  - SHA-256 content digest for integrity checking

OTA package format (binary, big-endian):
  [4 bytes] magic: 0xA1F0A500
  [4 bytes] version: package format version
  [2 bytes] metadata_len
  [N bytes] metadata (JSON)
  [4 bytes] payload_len
  [M bytes] payload
  [32 bytes] signature (HMAC-SHA256)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_MAGIC   = 0xA1F0A500
_VERSION = 1


@dataclass
class OTAPackageMetadata:
    package_id:       str
    target_version:   str     # SemVer of the payload being delivered
    min_device_version: str   # device must be >= this to accept
    device_class:     str
    payload_type:     str     # "model" | "firmware" | "config"
    payload_sha256:   str
    payload_size:     int
    created_at:       str
    signer:           str


@dataclass
class OTAPackage:
    metadata:  OTAPackageMetadata
    payload:   bytes
    signature: bytes     # HMAC-SHA256 over metadata JSON + payload

    def save(self, path: str | Path) -> None:
        meta_bytes = json.dumps(self.metadata.__dict__).encode()
        header     = struct.pack(">IIH", _MAGIC, _VERSION, len(meta_bytes))
        payload_hdr = struct.pack(">I", len(self.payload))
        blob = header + meta_bytes + payload_hdr + self.payload + self.signature
        Path(path).write_bytes(blob)


class OTAPackageBuilder:
    """
    Builds and signs OTA update packages.

    Parameters
    ----------
    signing_key  : HMAC-SHA256 signing key (≥ 32 bytes).
    signer       : Identity string recorded in the package.
    """

    def __init__(self, signing_key: bytes, signer: str = "ota-server"):
        if len(signing_key) < 32:
            raise ValueError("signing_key must be ≥ 32 bytes")
        self._key    = signing_key
        self._signer = signer

    def build(
        self,
        payload:          bytes,
        target_version:   str,
        device_class:     str,
        payload_type:     str    = "model",
        min_device_version: str  = "0.0.0",
    ) -> OTAPackage:
        import uuid
        sha256  = hashlib.sha256(payload).hexdigest()
        meta    = OTAPackageMetadata(
            package_id         = str(uuid.uuid4()),
            target_version     = target_version,
            min_device_version = min_device_version,
            device_class       = device_class,
            payload_type       = payload_type,
            payload_sha256     = sha256,
            payload_size       = len(payload),
            created_at         = datetime.now(timezone.utc).isoformat(),
            signer             = self._signer,
        )
        meta_bytes = json.dumps(meta.__dict__).encode()
        signature  = hmac.new(
            self._key, meta_bytes + payload, hashlib.sha256
        ).digest()

        return OTAPackage(metadata=meta, payload=payload, signature=signature)

    @staticmethod
    def load(path: str | Path) -> tuple:
        """Load a saved OTA package. Returns (metadata_dict, payload, signature)."""
        data   = Path(path).read_bytes()
        magic, ver, meta_len = struct.unpack_from(">IIH", data, 0)
        if magic != _MAGIC:
            raise ValueError("Invalid OTA package magic number")
        offset    = struct.calcsize(">IIH")
        meta_dict = json.loads(data[offset: offset + meta_len])
        offset   += meta_len
        pay_len,  = struct.unpack_from(">I", data, offset)
        offset   += 4
        payload   = data[offset: offset + pay_len]
        signature = data[offset + pay_len:]
        return meta_dict, payload, signature
