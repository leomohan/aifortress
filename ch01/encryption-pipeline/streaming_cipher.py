"""
streaming_cipher.py  —  Chunked AES-256-GCM for large dataset files
AI Fortress · Chapter 1 · Code Sample 1.A

File format on disk:
  [8 bytes]  magic b"AIFRT1\\x00\\x00"
  [4 bytes]  chunk_size (big-endian uint32) — plaintext bytes per chunk
  per chunk:
    [4 bytes]  chunk_body_len (big-endian uint32)
    [12 bytes] nonce (random per chunk)
    [N bytes]  AES-GCM ciphertext  (plaintext + 16-byte tag)
  [8 bytes]  trailer b"AIFEND\\x00\\x00"

Every chunk carries an independent GCM tag — tampering with any single chunk
raises InvalidTag before any plaintext is written for that chunk.
"""
from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm

MAGIC              = b"AIFRT1\x00\x00"
TRAILER            = b"AIFEND\x00\x00"
DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024   # 64 MB


def encrypt_stream(
    dek:           bytes,
    input_path:    Path,
    output_path:   Path,
    chunk_size:    int  = DEFAULT_CHUNK_SIZE,
    show_progress: bool = True,
) -> str:
    """
    Encrypt input_path to output_path with AES-256-GCM.
    Returns the hex SHA-256 of the plaintext (computed during encryption).
    """
    aesgcm   = AESGCM(dek)
    sha256   = hashlib.sha256()
    filesize = input_path.stat().st_size
    n_chunks = max(1, (filesize + chunk_size - 1) // chunk_size)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        fout.write(MAGIC)
        fout.write(struct.pack(">I", chunk_size))

        with tqdm(total=n_chunks, unit="chunk",
                  desc=f"Encrypting {input_path.name}", disable=not show_progress) as bar:
            while True:
                plaintext = fin.read(chunk_size)
                if not plaintext:
                    break
                sha256.update(plaintext)
                nonce      = os.urandom(12)
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                body       = nonce + ciphertext
                fout.write(struct.pack(">I", len(body)))
                fout.write(body)
                bar.update(1)

        fout.write(TRAILER)

    return sha256.hexdigest()


def decrypt_stream(
    dek:             bytes,
    input_path:      Path,
    output_path:     Path,
    expected_sha256: str  = "",
    show_progress:   bool = True,
) -> str:
    """
    Decrypt input_path to output_path.
    Raises ValueError on bad magic/trailer, InvalidTag on GCM failure.
    Returns hex SHA-256 of decrypted plaintext; verifies against expected_sha256 if given.
    """
    aesgcm = AESGCM(dek)
    sha256 = hashlib.sha256()

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        magic = fin.read(8)
        if magic != MAGIC:
            raise ValueError(f"Bad magic bytes {magic!r} — not an AI Fortress encrypted file")

        _chunk_size = struct.unpack(">I", fin.read(4))[0]  # informational only

        with tqdm(unit="chunk", desc=f"Decrypting {input_path.name}",
                  disable=not show_progress) as bar:
            while True:
                raw = fin.read(4)
                if len(raw) < 4:
                    raise ValueError("Unexpected EOF — missing trailer")

                # Peek: could this be the start of TRAILER?
                if raw == TRAILER[:4]:
                    trailer_rest = fin.read(4)
                    if trailer_rest == TRAILER[4:]:
                        break   # clean end
                    raise ValueError("Malformed trailer")

                chunk_len  = struct.unpack(">I", raw)[0]
                chunk_body = fin.read(chunk_len)
                if len(chunk_body) != chunk_len:
                    raise ValueError("Truncated chunk in encrypted file")

                nonce     = chunk_body[:12]
                ciphertext = chunk_body[12:]
                plaintext  = aesgcm.decrypt(nonce, ciphertext, None)  # raises InvalidTag on failure
                sha256.update(plaintext)
                fout.write(plaintext)
                bar.update(1)

    actual = sha256.hexdigest()
    if expected_sha256 and actual != expected_sha256:
        raise ValueError(
            f"Integrity FAILED: expected {expected_sha256}, got {actual}"
        )
    return actual


def plaintext_sha256(path: Path) -> str:
    """SHA-256 of a plaintext file without encrypting."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in _read_chunks(f, DEFAULT_CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def _read_chunks(f, size: int) -> Iterator[bytes]:
    while True:
        data = f.read(size)
        if not data:
            break
        yield data
