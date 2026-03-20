"""
verify_integrity.py  —  In-memory integrity verification (no output file)
AI Fortress · Chapter 1 · Code Sample 1.A

Decrypts each chunk in memory, hashes the plaintext, and compares against
the manifest's recorded SHA-256.  No plaintext is written to disk.
Exit 0 = PASS, Exit 1 = FAIL.
"""
from __future__ import annotations
import hashlib, struct, sys
from pathlib import Path
import click
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from tqdm import tqdm
from streaming_cipher import MAGIC, TRAILER
from manifest import load_manifest, get_dataset_wrapped_key
from envelope_key import unwrap_dek


@click.command()
@click.option("--encrypted-file", required=True, type=click.Path(exists=True))
@click.option("--manifest",       default="", type=click.Path())
@click.option("--quiet",          is_flag=True, default=False)
def verify(encrypted_file, manifest, quiet):
    """Verify GCM tags and SHA-256 of an encrypted dataset without writing plaintext to disk."""
    enc = Path(encrypted_file)
    mf  = Path(manifest) if manifest else enc.parent / (enc.name + ".manifest.enc")

    if not mf.exists():
        click.secho(f"ERROR: Manifest not found at {mf}", fg="red"); sys.exit(1)

    if not quiet:
        click.echo(f"Manifest : {mf}")
    m   = load_manifest(mf)
    wk  = get_dataset_wrapped_key(m)
    dek = unwrap_dek(wk)

    if not quiet:
        click.echo(f"File     : {enc}")
        click.echo(f"Expected : {m.plaintext_sha256}")

    sha256 = hashlib.sha256()
    aesgcm = AESGCM(dek)
    errors = []
    chunk_idx = 0

    with open(enc, "rb") as f:
        if f.read(8) != MAGIC:
            click.secho("FAIL: Bad magic bytes.", fg="red"); sys.exit(1)
        f.read(4)  # skip stored chunk_size

        bar = tqdm(unit="chunk", desc="Verifying", disable=quiet)
        while True:
            raw = f.read(4)
            if len(raw) < 4:
                errors.append("Unexpected EOF — missing trailer"); break

            if raw == TRAILER[:4]:
                rest = f.read(4)
                if rest == TRAILER[4:]:
                    break
                errors.append("Malformed trailer"); break

            chunk_len  = struct.unpack(">I", raw)[0]
            chunk_body = f.read(chunk_len)
            if len(chunk_body) != chunk_len:
                errors.append(f"Chunk {chunk_idx}: truncated"); break

            try:
                plaintext = aesgcm.decrypt(chunk_body[:12], chunk_body[12:], None)
                sha256.update(plaintext)
            except Exception as e:
                errors.append(f"Chunk {chunk_idx}: GCM tag FAILED — {e}")
            chunk_idx += 1
            bar.update(1)
        bar.close()

    actual = sha256.hexdigest()

    if errors:
        click.secho("INTEGRITY VERIFICATION FAILED", fg="red", bold=True)
        for e in errors:
            click.secho(f"  ✗ {e}", fg="red")
        sys.exit(1)

    if actual != m.plaintext_sha256:
        click.secho("INTEGRITY FAILED — SHA-256 MISMATCH", fg="red", bold=True)
        click.echo(f"  Expected : {m.plaintext_sha256}")
        click.echo(f"  Actual   : {actual}")
        sys.exit(1)

    if not quiet:
        click.secho("✓ Integrity PASSED", fg="green", bold=True)
        click.echo(f"  SHA-256 : {actual}  ({chunk_idx} chunks)")
    sys.exit(0)


if __name__ == "__main__":
    verify()
