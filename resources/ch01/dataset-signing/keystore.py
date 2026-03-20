"""
keystore.py  —  Ed25519 key generation and management
AI Fortress · Chapter 1 · Code Sample 1.C
"""
from __future__ import annotations
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def save_private_key(key: Ed25519PrivateKey, path: Path, password: bytes | None = None) -> None:
    enc = (serialization.BestAvailableEncryption(password)
           if password else serialization.NoEncryption())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    path.write_bytes(pem)
    path.chmod(0o600)


def save_public_key(key: Ed25519PublicKey, path: Path) -> None:
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=password)


def load_public_key(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def find_public_key_for_fingerprint(fingerprint: str, keys_dir: Path) -> Ed25519PublicKey | None:
    """Search keys_dir for a .public.pem file whose fingerprint matches."""
    from provenance import key_fingerprint
    for pem_file in keys_dir.glob("*.public.pem"):
        try:
            pk = load_public_key(pem_file)
            if key_fingerprint(pk) == fingerprint:
                return pk
        except Exception:
            continue
    return None
