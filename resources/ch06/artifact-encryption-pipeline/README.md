# Ch.06-A — Model Encryption & Signing

**AI Fortress** · Chapter 6: Model Encryption, Signing & IP Protection

---

## What This Does

Protects model artefacts (checkpoint files, ONNX exports, weight shards)
at rest and in transit with five security controls:

- **Model encryptor** — encrypts checkpoint files with AES-256-GCM using a
  fresh DEK per file; wraps the DEK under a KEK stored in AWS KMS or HashiCorp
  Vault (envelope encryption pattern from Chapter 1, adapted for model files);
  supports streaming encryption of multi-GB checkpoint shards
- **Ed25519 signer** — signs the encrypted model artefact + metadata (model
  name, version, SHA-256, timestamp) with an Ed25519 private key; produces a
  detached `.sig` signature file; verifies before any load operation
- **Signature verifier** — verifies Ed25519 signatures before model loading;
  rejects any checkpoint whose signature is missing, invalid, or whose
  SHA-256 does not match; can verify a chain of provenance signatures
- **Key rotation manager** — re-wraps the model DEK under a new KEK without
  decrypting the model weights; useful for periodic key rotation policy
  compliance; produces a rotation audit certificate
- **Load guard** — a drop-in wrapper for `torch.load` / `tf.saved_model.load`
  that enforces signature verification before returning the model object;
  raises `UnsignedModelError` if verification fails

---

## File Structure

```
model-encryption-signing/
├── README.md
├── requirements.txt
├── model_encryptor.py         # AES-256-GCM envelope encryption for checkpoints
├── model_signer.py            # Ed25519 signing and signature manifest
├── signature_verifier.py      # Verification pipeline with chain support
├── key_rotation.py            # DEK re-wrapping without weight decryption
├── load_guard.py              # Safe model loader with mandatory verification
└── tests/
    └── test_model_encryption_signing.py
```

## Quick Start

```python
from model_encryptor import ModelEncryptor
from model_signer import ModelSigner
from load_guard import SafeModelLoader

# Encrypt a checkpoint
enc = ModelEncryptor(backend="local")
enc.encrypt("model_v1.pt", "model_v1.pt.enc")

# Sign the encrypted artefact
signer = ModelSigner.from_new_keypair()
signer.sign("model_v1.pt.enc", metadata={"model": "fraud-detector", "version": "1.0"})

# Safe load (verifies signature before returning)
loader = SafeModelLoader(public_key_path="signing.pub")
model  = loader.load("model_v1.pt.enc")
```

## Run Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```
