"""
encrypt_dataset.py  —  CLI for AI Fortress training data encryption
AI Fortress · Chapter 1 · Code Sample 1.A

Commands:
  encrypt   Encrypt a dataset file (AES-256-GCM, envelope key)
  decrypt   Decrypt an encrypted dataset file
  info      Display manifest metadata without decrypting the dataset
"""
from __future__ import annotations
import sys
from pathlib import Path
import click
from envelope_key import KeyBackend, generate_dek, unwrap_dek
from streaming_cipher import encrypt_stream, decrypt_stream, DEFAULT_CHUNK_SIZE
from manifest import create_manifest, save_manifest, load_manifest, get_dataset_wrapped_key


def _backend_options(f):
    f = click.option("--backend",        type=click.Choice(["kms","vault"]), default="kms", show_default=True)(f)
    f = click.option("--kms-key-id",     default="", help="AWS KMS key ARN or alias")(f)
    f = click.option("--vault-key-name", default="", help="Vault Transit key name")(f)
    return f


@click.group()
def cli():
    """AI Fortress — Training Data Encryption Pipeline (Chapter 1)"""


@cli.command()
@click.option("--input",  "inp", required=True,  type=click.Path(exists=True))
@click.option("--output", "out", required=True,  type=click.Path())
@click.option("--manifest-out",    default="")
@click.option("--chunk-size",      default=DEFAULT_CHUNK_SIZE, show_default=True)
@click.option("--classification",  default="CONFIDENTIAL", show_default=True)
@click.option("--owner",           default="")
@click.option("--dataset-id",      default="")
@_backend_options
def encrypt(inp, out, manifest_out, chunk_size, classification, owner, dataset_id,
            backend, kms_key_id, vault_key_name):
    """Encrypt a training dataset with AES-256-GCM envelope encryption."""
    i  = Path(inp);  o = Path(out)
    mf = Path(manifest_out) if manifest_out else o.parent / (o.name + ".manifest.enc")
    kb = KeyBackend(backend)

    click.echo("[1/3] Generating DEK ...")
    dek, wk = generate_dek(backend=kb, kms_key_id=kms_key_id, vault_key_name=vault_key_name)

    click.echo(f"[2/3] Encrypting {i.name} ...")
    digest = encrypt_stream(dek, i, o, chunk_size=chunk_size)

    click.echo(f"[3/3] Writing manifest ...")
    manifest = create_manifest(i, digest, chunk_size, wk, classification, owner, dataset_id)
    save_manifest(manifest, mf, kb, kms_key_id, vault_key_name)

    click.secho("\n✓ Done.", fg="green")
    click.echo(f"  SHA-256   : {digest}")
    click.echo(f"  Encrypted : {o}")
    click.echo(f"  Manifest  : {mf}")


@cli.command()
@click.option("--input",    "inp", required=True, type=click.Path(exists=True))
@click.option("--output",   "out", required=True, type=click.Path())
@click.option("--manifest", "mfp", default="")
@click.option("--verify/--no-verify", default=True, show_default=True)
@_backend_options
def decrypt(inp, out, mfp, verify, backend, kms_key_id, vault_key_name):
    """Decrypt an encrypted training dataset."""
    i  = Path(inp); o = Path(out)
    mf = Path(mfp) if mfp else i.parent / (i.name + ".manifest.enc")

    if not mf.exists():
        click.secho("[warn] No manifest found — skipping integrity check.", fg="yellow")
        verify = False

    expected = ""
    wk       = None

    if mf.exists():
        click.echo(f"[1/3] Loading manifest ...")
        m        = load_manifest(mf)
        wk       = get_dataset_wrapped_key(m)
        expected = m.plaintext_sha256 if verify else ""
        click.echo(f"      Original  : {m.original_filename}")
        click.echo(f"      Encrypted : {m.encrypted_at}")
    else:
        click.secho("ERROR: No manifest and no key reference available.", fg="red"); sys.exit(1)

    click.echo("[2/3] Unwrapping DEK ...")
    dek = unwrap_dek(wk)

    click.echo(f"[3/3] Decrypting ...")
    actual = decrypt_stream(dek, i, o, expected_sha256=expected)

    click.secho("\n✓ Done.", fg="green")
    click.echo(f"  SHA-256   : {actual}")
    if verify and expected:
        click.secho("  Integrity : PASSED", fg="green")


@cli.command()
@click.option("--input", "inp", required=True, type=click.Path(exists=True),
              help="Manifest file (.manifest.enc)")
def info(inp):
    """Display metadata from an encrypted dataset manifest."""
    m = load_manifest(Path(inp))
    click.echo("\nAI Fortress — Dataset Manifest")
    click.echo("=" * 44)
    click.echo(f"  Schema        : {m.schema_version}")
    click.echo(f"  File          : {m.original_filename}")
    click.echo(f"  Dataset ID    : {m.dataset_id or '(not set)'}")
    click.echo(f"  Classification: {m.classification}")
    click.echo(f"  Owner         : {m.owner or '(not set)'}")
    click.echo(f"  Encrypted at  : {m.encrypted_at}")
    click.echo(f"  Chunk size    : {m.chunk_size // (1024*1024)} MB")
    click.echo(f"  SHA-256       : {m.plaintext_sha256}")
    click.echo(f"  Key backend   : {m.wrapped_key.get('backend','?')}")
    if m.wrapped_key.get("kms_key_id"):
        click.echo(f"  KMS key       : {m.wrapped_key['kms_key_id']}")
    if m.wrapped_key.get("vault_key_name"):
        click.echo(f"  Vault key     : {m.wrapped_key['vault_key_name']}")


if __name__ == "__main__":
    cli()
