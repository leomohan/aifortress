# Ch.01-A — Training Data Encryption Pipeline

**AI Fortress** · Chapter 1: Data Confidentiality & Integrity

---

## What This Does

End-to-end AES-256-GCM encryption pipeline for ML training datasets:

- **Envelope encryption** — per-dataset DEK wrapped by a KEK in AWS KMS or HashiCorp Vault Transit
- **Streaming encryption** — 64 MB chunks; handles datasets larger than available RAM
- **Authenticated encryption** — GCM tags verified on every chunk before plaintext is written
- **Encrypted manifest** — provenance metadata (SHA-256, key reference, timestamp) stored alongside each artifact and itself encrypted
- **Key rotation** — re-wrap DEK under a new KEK without touching the dataset ciphertext
- **Integrity verification** — verify GCM tags + SHA-256 in-memory without writing plaintext to disk

## File Structure

```
encryption-pipeline/
├── README.md
├── requirements.txt
├── envelope_key.py       # DEK generation, KMS/Vault wrap/unwrap/rewrap
├── streaming_cipher.py   # Chunked AES-256-GCM encrypt/decrypt
├── manifest.py           # Encrypted manifest create/save/load
├── encrypt_dataset.py    # CLI: encrypt | decrypt | info
├── key_rotation.py       # Re-wrap DEK under new KMS key
├── verify_integrity.py   # Standalone integrity checker (no output file)
└── tests/
    └── test_encrypt_decrypt.py
```

## Quick Start

```bash
pip install -r requirements.txt

# Encrypt
python encrypt_dataset.py encrypt \
  --input data/train.parquet \
  --output data/train.parquet.enc \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/mrk-abc123 \
  --backend kms

# Decrypt
python encrypt_dataset.py decrypt \
  --input data/train.parquet.enc \
  --output data/train.parquet \
  --backend kms

# Verify integrity without decrypting
python verify_integrity.py --encrypted-file data/train.parquet.enc

# Rotate KEK
python key_rotation.py rotate \
  --encrypted-file data/train.parquet.enc \
  --old-kms-key-id arn:aws:kms:...:key/old \
  --new-kms-key-id arn:aws:kms:...:key/new

# Run tests
pytest tests/ -v
```

## Security Notes

- DEKs exist in memory only during encrypt/decrypt; never written to disk in plaintext
- GCM authentication tags verified before any plaintext byte is output
- Manifest encrypted under same KEK — metadata does not leak key references in plaintext
- For Vault backend: set `VAULT_ADDR` and `VAULT_TOKEN` env vars; never pass as CLI args
