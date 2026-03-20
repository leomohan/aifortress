"""
tests/test_provenance.py  —  Sign, verify, chain tests
AI Fortress · Chapter 1 · Code Sample 1.C
Run: pytest tests/ -v
"""
from __future__ import annotations
import os
from pathlib import Path
import pytest
from cryptography.exceptions import InvalidSignature
from keystore import generate_keypair, save_private_key, save_public_key
from provenance import sign_artifact, verify_record, provenance_path_for, ProvenanceRecord
from chain import verify_chain, ChainVerificationError


@pytest.fixture
def keypair():
    return generate_keypair()

@pytest.fixture
def artifact(tmp_path):
    p = tmp_path / "train.parquet"
    p.write_bytes(os.urandom(1024))
    return p

@pytest.fixture
def keys_dir(tmp_path, keypair):
    kd = tmp_path / "keys"; kd.mkdir()
    priv, pub = keypair
    save_private_key(priv, kd / "ingest.private.pem")
    save_public_key(pub, kd / "ingest.public.pem")
    return kd, priv, pub


class TestSingleRecord:
    def test_sign_and_verify(self, keypair, artifact):
        priv, pub = keypair
        record = sign_artifact(artifact, "ingest", priv, pub, source_uri="s3://src/f.parquet")
        assert record.artifact_sha256
        assert record.signature
        assert verify_record(record, pub) is True

    def test_is_root_when_no_parent(self, keypair, artifact):
        priv, pub = keypair
        record = sign_artifact(artifact, "ingest", priv, pub)
        assert record.is_root

    def test_tampered_artifact_path_invalidates_sig(self, keypair, artifact):
        priv, pub = keypair
        record = sign_artifact(artifact, "ingest", priv, pub)
        record.artifact_path = "/evil/path"    # tamper
        with pytest.raises(InvalidSignature):
            verify_record(record, pub)

    def test_wrong_key_invalidates_sig(self, keypair, artifact):
        priv, pub = keypair
        record    = sign_artifact(artifact, "ingest", priv, pub)
        _, pub2   = generate_keypair()
        with pytest.raises(InvalidSignature):
            verify_record(record, pub2)

    def test_roundtrip_json(self, keypair, artifact, tmp_path):
        priv, pub = keypair
        record    = sign_artifact(artifact, "ingest", priv, pub)
        path      = tmp_path / "record.provenance.json"
        record.save(path)
        loaded = ProvenanceRecord.load(path)
        assert verify_record(loaded, pub) is True


class TestChain:
    def test_two_link_chain(self, tmp_path):
        kd = tmp_path / "keys"; kd.mkdir()
        priv_i, pub_i = generate_keypair()
        priv_t, pub_t = generate_keypair()
        save_public_key(pub_i, kd / "ingest.public.pem")
        save_public_key(pub_t, kd / "transform.public.pem")

        # Artifact 1: root
        a1 = tmp_path / "raw.parquet";  a1.write_bytes(os.urandom(512))
        r1 = sign_artifact(a1, "ingest", priv_i, pub_i, source_uri="s3://src/raw.parquet")
        p1 = tmp_path / "raw.parquet.provenance.json"; r1.save(p1)

        # Artifact 2: child
        a2 = tmp_path / "clean.parquet"; a2.write_bytes(os.urandom(512))
        r2 = sign_artifact(a2, "transform", priv_t, pub_t,
                            parent_record_id=r1.record_id, transformation="PII removed")
        p2 = tmp_path / "clean.parquet.provenance.json"; r2.save(p2)

        chain = verify_chain(p2, kd, provenance_dir=tmp_path)
        assert len(chain) == 2
        assert chain[0].record.record_id == r2.record_id
        assert chain[1].record.record_id == r1.record_id
        assert chain[1].record.is_root

    def test_tampered_record_breaks_chain(self, tmp_path):
        kd = tmp_path / "keys"; kd.mkdir()
        priv, pub = generate_keypair()
        save_public_key(pub, kd / "ingest.public.pem")
        a = tmp_path / "data.parquet"; a.write_bytes(os.urandom(512))
        r = sign_artifact(a, "ingest", priv, pub)
        p = tmp_path / "data.parquet.provenance.json"
        # Tamper before saving
        import json
        d = json.loads(r.to_json()); d["artifact_path"] = "/evil"
        p.write_text(json.dumps(d), encoding="utf-8")

        with pytest.raises(ChainVerificationError, match="Signature INVALID"):
            verify_chain(p, kd, provenance_dir=tmp_path)
