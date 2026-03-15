"""
tests/test_encrypt_decrypt.py  —  Round-trip and tamper tests
AI Fortress · Chapter 1 · Code Sample 1.A
Run: pytest tests/ -v
"""
from __future__ import annotations
import os
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from streaming_cipher import encrypt_stream, decrypt_stream


@pytest.fixture
def dek():
    return AESGCM.generate_key(bit_length=256)

@pytest.fixture
def small_file(tmp_path):
    p = tmp_path / "train.parquet"
    p.write_bytes(os.urandom(1 * 1024 * 1024))
    return p

@pytest.fixture
def multi_chunk_file(tmp_path):
    p = tmp_path / "train_large.parquet"
    p.write_bytes(os.urandom(10 * 1024 * 1024))
    return p


class TestRoundtrip:
    def test_small(self, dek, small_file, tmp_path):
        enc = tmp_path / "train.enc"
        dec = tmp_path / "train_dec.parquet"
        d1  = encrypt_stream(dek, small_file, enc, show_progress=False)
        d2  = decrypt_stream(dek, enc, dec, expected_sha256=d1, show_progress=False)
        assert d1 == d2
        assert dec.read_bytes() == small_file.read_bytes()

    def test_multi_chunk(self, dek, multi_chunk_file, tmp_path):
        enc = tmp_path / "large.enc"
        dec = tmp_path / "large_dec.parquet"
        d1  = encrypt_stream(dek, multi_chunk_file, enc, chunk_size=4*1024*1024, show_progress=False)
        d2  = decrypt_stream(dek, enc, dec, expected_sha256=d1, show_progress=False)
        assert d1 == d2

    def test_empty_file(self, dek, tmp_path):
        src = tmp_path / "empty.bin"; src.write_bytes(b"")
        enc = tmp_path / "empty.enc"
        dec = tmp_path / "empty_dec.bin"
        d1  = encrypt_stream(dek, src, enc, show_progress=False)
        d2  = decrypt_stream(dek, enc, dec, expected_sha256=d1, show_progress=False)
        assert d1 == d2
        assert dec.read_bytes() == b""


class TestTamper:
    def test_tampered_ciphertext_raises(self, dek, small_file, tmp_path):
        enc = tmp_path / "tampered.enc"
        decrypt_stream  # import used below
        encrypt_stream(dek, small_file, enc, show_progress=False)
        raw = bytearray(enc.read_bytes())
        raw[50] ^= 0xFF
        enc.write_bytes(bytes(raw))
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            decrypt_stream(dek, enc, tmp_path / "out.parquet", show_progress=False)

    def test_wrong_key_raises(self, dek, small_file, tmp_path):
        enc      = tmp_path / "wrongkey.enc"
        wrong    = AESGCM.generate_key(bit_length=256)
        encrypt_stream(dek, small_file, enc, show_progress=False)
        from cryptography.exceptions import InvalidTag
        with pytest.raises(InvalidTag):
            decrypt_stream(wrong, enc, tmp_path / "out.parquet", show_progress=False)

    def test_bad_expected_sha256_raises(self, dek, small_file, tmp_path):
        enc = tmp_path / "sha.enc"
        encrypt_stream(dek, small_file, enc, show_progress=False)
        with pytest.raises(ValueError, match="Integrity FAILED"):
            decrypt_stream(dek, enc, tmp_path / "out.parquet",
                           expected_sha256="0"*64, show_progress=False)
