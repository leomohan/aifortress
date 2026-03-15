"""
cli.py  —  Data Provenance Signing CLI
AI Fortress · Chapter 1 · Code Sample 1.C
"""
from __future__ import annotations
from pathlib import Path
import click
from keystore import generate_keypair, save_private_key, save_public_key, load_private_key, load_public_key
from provenance import sign_artifact, verify_record, provenance_path_for, ProvenanceRecord
from chain import verify_chain, print_chain, ChainVerificationError


@click.group()
def cli():
    """AI Fortress — Data Provenance Signing (Chapter 1)"""


@cli.command()
@click.option("--stage",      required=True, help="Pipeline stage name, e.g. 'ingest'")
@click.option("--output-dir", default="keys", show_default=True)
def keygen(stage, output_dir):
    """Generate an Ed25519 key pair for a pipeline stage."""
    out  = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    priv = out / f"{stage}.private.pem"
    pub  = out / f"{stage}.public.pem"
    private_key, public_key = generate_keypair()
    save_private_key(private_key, priv)
    save_public_key(public_key, pub)
    click.secho(f"✓ Key pair generated for stage '{stage}'", fg="green")
    click.echo(f"  Private key : {priv}  (chmod 600 — keep secret)")
    click.echo(f"  Public key  : {pub}")


@cli.command()
@click.option("--file",               "artifact", required=True, type=click.Path(exists=True))
@click.option("--stage",              required=True)
@click.option("--private-key",        required=True, type=click.Path(exists=True))
@click.option("--source-uri",         default="")
@click.option("--transformation",     default="")
@click.option("--parent-provenance",  default="", type=click.Path(),
              help="Path to parent record's .provenance.json")
@click.option("--output",             default="", help="Output path (default: <artifact>.provenance.json)")
def sign(artifact, stage, private_key, source_uri, transformation, parent_provenance, output):
    """Sign an artifact and create a provenance record."""
    art   = Path(artifact)
    priv  = load_private_key(Path(private_key))
    pub   = priv.public_key()

    parent_id = ""
    if parent_provenance and Path(parent_provenance).exists():
        parent_record = ProvenanceRecord.load(Path(parent_provenance))
        parent_id = parent_record.record_id

    click.echo(f"Signing {art.name} ...")
    record = sign_artifact(
        artifact_path    = art,
        pipeline_stage   = stage,
        private_key      = priv,
        public_key       = pub,
        source_uri       = source_uri,
        transformation   = transformation,
        parent_record_id = parent_id,
    )

    out_path = Path(output) if output else provenance_path_for(art)
    record.save(out_path)
    click.secho(f"✓ Signed. Provenance record: {out_path}", fg="green")
    click.echo(f"  Record ID  : {record.record_id}")
    click.echo(f"  SHA-256    : {record.artifact_sha256}")
    click.echo(f"  Stage      : {record.pipeline_stage}")
    click.echo(f"  Root       : {record.is_root}")


@cli.command()
@click.option("--provenance",  required=True, type=click.Path(exists=True))
@click.option("--public-key",  required=True, type=click.Path(exists=True))
def verify(provenance, public_key):
    """Verify a single provenance record's signature."""
    record = ProvenanceRecord.load(Path(provenance))
    pub    = load_public_key(Path(public_key))
    try:
        verify_record(record, pub)
        click.secho(f"✓ Signature VALID — {record.record_id}", fg="green")
    except Exception as e:
        click.secho(f"✗ Signature INVALID — {e}", fg="red")
        raise SystemExit(1)


@cli.command()
@click.option("--provenance",  required=True, type=click.Path(exists=True),
              help="Leaf provenance record to start chain walk from")
@click.option("--keys-dir",    default="keys", show_default=True,
              help="Directory containing *.public.pem files")
def chain(provenance, keys_dir):
    """Walk and verify the full provenance chain from a leaf artifact to its root."""
    try:
        links = verify_chain(Path(provenance), Path(keys_dir))
        print_chain(links)
        click.secho(f"✓ All {len(links)} records verified.", fg="green")
    except ChainVerificationError as e:
        click.secho(f"✗ Chain verification FAILED: {e}", fg="red")
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
