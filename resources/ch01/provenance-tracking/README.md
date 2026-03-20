# Ch.01-C — Data Provenance Signing

**AI Fortress** · Chapter 1: Data Confidentiality & Integrity

---

## What This Does

Cryptographic chain-of-custody for ML training datasets — every artifact that
passes through the pipeline carries a signed provenance record linking it
unambiguously to its origin and every transformation applied to it:

- **Ed25519 signatures** — fast, compact, modern elliptic-curve signing (RFC 8032)
- **Provenance records** — JSON documents recording artifact SHA-256, pipeline stage, signer key fingerprint, timestamp, source URI, transformation description, and parent record ID
- **Chain-of-custody walker** — verifies every record from a downstream artifact back to the root ingestion event; fails immediately on any broken link or missing signature
- **Key management** — per-stage Ed25519 key generation, public key registry, PEM serialisation
- **CLI** — `keygen`, `sign`, `verify`, `chain` subcommands

## File Structure

```
data-provenance-signing/
├── README.md
├── requirements.txt
├── provenance.py     # Record creation, signing, single-record verification
├── chain.py          # Chain-of-custody walker and full-chain verifier
├── keystore.py       # Ed25519 key generation, PEM I/O, public key registry
├── cli.py            # Click CLI entry point
└── tests/
    └── test_provenance.py
```

## Quick Start

```bash
pip install -r requirements.txt

# Generate per-stage key pairs
python cli.py keygen --stage ingest    --output-dir keys/
python cli.py keygen --stage transform --output-dir keys/

# Sign artifact at ingestion
python cli.py sign \
  --file data/raw/customers.parquet \
  --stage ingest \
  --private-key keys/ingest.private.pem \
  --source-uri s3://source-bucket/customers_20240115.parquet \
  --transformation "Raw ingestion from source bucket"

# Sign transformed artifact (referencing parent)
python cli.py sign \
  --file data/processed/customers_clean.parquet \
  --stage transform \
  --private-key keys/transform.private.pem \
  --source-uri data/raw/customers.parquet \
  --parent-provenance data/raw/customers.parquet.provenance.json \
  --transformation "PII columns removed; nulls imputed"

# Verify single record
python cli.py verify \
  --provenance data/raw/customers.parquet.provenance.json \
  --public-key keys/ingest.public.pem

# Walk and verify full chain
python cli.py chain \
  --provenance data/processed/customers_clean.parquet.provenance.json \
  --keys-dir keys/

# Run tests
pytest tests/ -v
```
