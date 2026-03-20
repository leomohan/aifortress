"""
key_rotation.py  —  Re-wrap dataset DEK under a new KMS key
AI Fortress · Chapter 1 · Code Sample 1.A

Key rotation re-wraps the DEK stored in the manifest under a new KEK.
The dataset ciphertext is UNCHANGED — only the manifest is rewritten.
This is an O(1) operation regardless of dataset size.

For Vault: use `vault write transit/rewrap/<key> ciphertext=<ct>` directly.
"""
from __future__ import annotations
from dataclasses import asdict
from pathlib import Path
import click
from envelope_key import KeyBackend, rewrap_dek
from manifest import load_manifest, save_manifest, get_dataset_wrapped_key, DatasetManifest


@click.command()
@click.option("--encrypted-file",  required=True, type=click.Path(exists=True))
@click.option("--manifest",        default="", type=click.Path())
@click.option("--old-kms-key-id",  required=True)
@click.option("--new-kms-key-id",  required=True)
@click.option("--manifest-out",    default="", help="Defaults to overwriting existing manifest")
def rotate(encrypted_file, manifest, old_kms_key_id, new_kms_key_id, manifest_out):
    """Re-wrap dataset DEK under a new KMS key (KEK rotation)."""
    enc = Path(encrypted_file)
    mf  = Path(manifest) if manifest else enc.parent / (enc.name + ".manifest.enc")

    click.echo(f"[1/3] Loading manifest from {mf} ...")
    old_manifest = load_manifest(mf)
    old_wk       = get_dataset_wrapped_key(old_manifest)

    if old_wk.backend != "kms":
        click.secho("ERROR: Script only supports KMS. For Vault use Transit rewrap.", fg="red")
        raise SystemExit(1)

    click.echo(f"[2/3] Re-wrapping DEK:  {old_kms_key_id}  →  {new_kms_key_id} ...")
    _plaintext_dek, new_wk = rewrap_dek(old_wk, new_kms_key_id)

    click.echo(f"[3/3] Writing updated manifest ...")
    new_manifest = DatasetManifest(
        schema_version    = old_manifest.schema_version,
        original_filename = old_manifest.original_filename,
        plaintext_sha256  = old_manifest.plaintext_sha256,
        encrypted_at      = old_manifest.encrypted_at,
        chunk_size        = old_manifest.chunk_size,
        wrapped_key       = asdict(new_wk),
        classification    = old_manifest.classification,
        owner             = old_manifest.owner,
        dataset_id        = old_manifest.dataset_id,
        notes             = old_manifest.notes + f" | KEK rotated to {new_kms_key_id}",
    )
    out_mf = Path(manifest_out) if manifest_out else mf
    save_manifest(new_manifest, out_mf, KeyBackend.KMS, kms_key_id=new_kms_key_id)

    click.secho("\n✓ Key rotation complete.", fg="green")
    click.echo(f"  Old KEK : {old_kms_key_id}")
    click.echo(f"  New KEK : {new_kms_key_id}")
    click.echo("  Dataset ciphertext unchanged.")
    click.echo("  Schedule old key deletion only after verifying no other datasets reference it.")


if __name__ == "__main__":
    rotate()
